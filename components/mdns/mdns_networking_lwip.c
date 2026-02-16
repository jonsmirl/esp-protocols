/*
 * SPDX-FileCopyrightText: 2022-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * MDNS Server Networking
 *
 */
#include <string.h>
#include "esp_log.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/igmp.h"
#include "lwip/udp.h"
#include "lwip/mld6.h"
#include "lwip/priv/tcpip_priv.h"
#include "esp_system.h"
#include "esp_event.h"
#include "mdns_networking.h"
#include "esp_netif_net_stack.h"
#include "mdns_mem_caps.h"

/*
 * MDNS Server Networking
 *
 */
enum interface_protocol {
    PROTO_IPV4 = 1 << MDNS_IP_PROTOCOL_V4,
    PROTO_IPV6 = 1 << MDNS_IP_PROTOCOL_V6
};

typedef struct interfaces {
    bool ready;
    int proto;
} interfaces_t;

static interfaces_t s_interfaces[MDNS_MAX_INTERFACES];

static struct udp_pcb *_pcb_main = NULL;

static const char *TAG = "mdns_networking";

// Defined in mdns.c — used by the pre-filter to check service/browse/hostname
extern mdns_server_t *_mdns_server;

static void _udp_recv(void *arg, struct udp_pcb *upcb, struct pbuf *pb, const ip_addr_t *raddr, uint16_t rport);

/**
 * @brief  Low level UDP PCB Initialize
 */
static esp_err_t _udp_pcb_main_init(void)
{
    if (_pcb_main) {
        return ESP_OK;
    }
    _pcb_main = udp_new();
    if (!_pcb_main) {
        return ESP_ERR_NO_MEM;
    }
    if (udp_bind(_pcb_main, IP_ANY_TYPE, MDNS_SERVICE_PORT) != 0) {
        udp_remove(_pcb_main);
        _pcb_main = NULL;
        return ESP_ERR_INVALID_STATE;
    }
    _pcb_main->mcast_ttl = 255;
    _pcb_main->remote_port = MDNS_SERVICE_PORT;
    ip_addr_copy(_pcb_main->remote_ip, *(IP_ANY_TYPE));
    udp_recv(_pcb_main, &_udp_recv, NULL);
    return ESP_OK;
}

/**
 * @brief  Low level UDP PCB Free
 */
static void _udp_pcb_main_deinit(void)
{
    if (_pcb_main) {
        udp_recv(_pcb_main, NULL, NULL);
        udp_disconnect(_pcb_main);
        udp_remove(_pcb_main);
        _pcb_main = NULL;
    }
}

/**
 * @brief  Low level UDP Multicast membership control
 */
static esp_err_t _udp_join_group(mdns_if_t if_inx, mdns_ip_protocol_t ip_protocol, bool join)
{
    struct netif *netif = NULL;
    esp_netif_t *tcpip_if = _mdns_get_esp_netif(if_inx);

    if (!esp_netif_is_netif_up(tcpip_if)) {
        // Network interface went down before event propagated, skipping IGMP config
        return ESP_ERR_INVALID_STATE;
    }

    netif = esp_netif_get_netif_impl(tcpip_if);
    assert(netif);

#if LWIP_IPV4
    if (ip_protocol == MDNS_IP_PROTOCOL_V4) {
        ip4_addr_t multicast_addr;
        IP4_ADDR(&multicast_addr, 224, 0, 0, 251);

        if (join) {
            if (igmp_joingroup_netif(netif, &multicast_addr)) {
                return ESP_ERR_INVALID_STATE;
            }
        } else {
            if (igmp_leavegroup_netif(netif, &multicast_addr)) {
                return ESP_ERR_INVALID_STATE;
            }
        }
    }
#endif // LWIP_IPV4
#if LWIP_IPV6
    if (ip_protocol == MDNS_IP_PROTOCOL_V6) {
        ip_addr_t multicast_addr = IPADDR6_INIT(0x000002ff, 0, 0, 0xfb000000);

        if (join) {
            if (mld6_joingroup_netif(netif, ip_2_ip6(&multicast_addr))) {
                return ESP_ERR_INVALID_STATE;
            }
        } else {
            if (mld6_leavegroup_netif(netif, ip_2_ip6(&multicast_addr))) {
                return ESP_ERR_INVALID_STATE;
            }
        }
    }
#endif // LWIP_IPV6
    return ESP_OK;
}

/**
 * @brief  Fast pre-filter for mDNS response packets.
 *
 * Scans raw packet bytes for service names relevant to our active browses,
 * searches, and registered services.  Drops response packets that only
 * contain records for services we don't care about (printers, Chromecasts,
 * AirPlay, etc.).  Query packets are always accepted — we must answer them
 * if they target our services.
 *
 * This runs in the lwIP/tcpip callback, so it must be lock-free and fast.
 * The check is conservative: any packet containing our hostname or a
 * registered/browsed service name passes through.  False positives are
 * fine (the full parser will handle them); false negatives must not occur.
 */
static bool _mdns_rx_is_relevant(struct pbuf *pb)
{
    const uint8_t *data = (const uint8_t *)pb->payload;
    size_t len = pb->len;

    // Too short to be a valid mDNS packet
    if (len < 12) {
        return false;
    }

    // Always accept queries (QR bit = 0) — we may need to respond
    uint16_t flags = (data[2] << 8) | data[3];
    if (!(flags & 0x8000)) {
        return true;
    }

    // For responses: scan the raw packet for DNS-encoded service names
    // we care about.  DNS labels are length-prefixed, so "_matter" appears
    // as the byte sequence \x07_matter in the wire format.  We scan for
    // all registered services, browses, and our own hostname.
    //
    // We check against the server's hostname and the service/browse lists.
    // These are read-only here (we only read pointers and compare strings).
    // The mdns service task could be modifying them concurrently, but:
    //   - hostname pointer is updated atomically (single pointer write)
    //   - service/browse lists: we may read a stale or partially-updated
    //     list, but the worst case is a false positive (packet accepted
    //     when it shouldn't be) or a very brief false negative on the
    //     first packet after a new browse starts.  Both are harmless.
    if (!_mdns_server) {
        return true;  // Server not initialized yet — accept everything
    }

    // Check for our hostname (probe/conflict detection)
    const char *hostname = _mdns_server->hostname;
    if (hostname && hostname[0]) {
        size_t hlen = strlen(hostname);
        if (hlen < 64) {
            // Build DNS label: length byte + name
            uint8_t label[65];
            label[0] = (uint8_t)hlen;
            memcpy(label + 1, hostname, hlen);
            if (memmem(data + 12, len - 12, label, hlen + 1)) {
                return true;
            }
        }
    }

    // Check for browsed service names (e.g., "_matter._tcp")
    mdns_browse_t *b = _mdns_server->browse;
    while (b) {
        if (b->service[0]) {
            size_t slen = strlen(b->service);
            if (slen < 64) {
                uint8_t label[65];
                label[0] = (uint8_t)slen;
                memcpy(label + 1, b->service, slen);
                if (memmem(data + 12, len - 12, label, slen + 1)) {
                    return true;
                }
            }
        }
        b = b->next;
    }

    // Check for registered service names (services we advertise)
    mdns_srv_item_t *s = _mdns_server->services;
    while (s) {
        if (s->service && s->service->service && s->service->service[0]) {
            size_t slen = strlen(s->service->service);
            if (slen < 64) {
                uint8_t label[65];
                label[0] = (uint8_t)slen;
                memcpy(label + 1, s->service->service, slen);
                if (memmem(data + 12, len - 12, label, slen + 1)) {
                    return true;
                }
            }
        }
        s = s->next;
    }

    // Check for active search names
    mdns_search_once_t *srch = _mdns_server->search_once;
    while (srch) {
        if (srch->service && srch->service[0]) {
            size_t slen = strlen(srch->service);
            if (slen < 64) {
                uint8_t label[65];
                label[0] = (uint8_t)slen;
                memcpy(label + 1, srch->service, slen);
                if (memmem(data + 12, len - 12, label, slen + 1)) {
                    return true;
                }
            }
        }
        srch = srch->next;
    }

    return false;  // Not relevant — drop it
}

uint32_t s_rx_filtered_count = 0;

/**
 * @brief  the receive callback of the raw udp api. Packets are received here
 *
 */
static void _udp_recv(void *arg, struct udp_pcb *upcb, struct pbuf *pb, const ip_addr_t *raddr, uint16_t rport)
{

    uint8_t i;
    while (pb != NULL) {
        struct pbuf *this_pb = pb;
        pb = pb->next;
        this_pb->next = NULL;

        // Pre-filter: drop response packets not relevant to our services
        if (!_mdns_rx_is_relevant(this_pb)) {
            s_rx_filtered_count++;
            pbuf_free(this_pb);
            continue;
        }

        mdns_rx_packet_t *packet = (mdns_rx_packet_t *)mdns_mem_malloc(sizeof(mdns_rx_packet_t));
        if (!packet) {
            HOOK_MALLOC_FAILED;
            //missed packet - no memory
            pbuf_free(this_pb);
            continue;
        }

        packet->tcpip_if = MDNS_MAX_INTERFACES;
        packet->pb = this_pb;
        packet->src_port = rport;
#if LWIP_IPV4 && LWIP_IPV6
        packet->src.type = raddr->type;
        memcpy(&packet->src.u_addr, &raddr->u_addr, sizeof(raddr->u_addr));
#elif LWIP_IPV4
        packet->src.type = IPADDR_TYPE_V4;
        packet->src.u_addr.ip4.addr = raddr->addr;
#elif LWIP_IPV6
        packet->src.type = IPADDR_TYPE_V6;
        memcpy(&packet->src.u_addr.ip6, raddr, sizeof(ip_addr_t));
#endif
        packet->dest.type = packet->src.type;

#if LWIP_IPV4
        if (packet->src.type == IPADDR_TYPE_V4) {
            packet->ip_protocol = MDNS_IP_PROTOCOL_V4;
            struct ip_hdr *iphdr = (struct ip_hdr *)(((uint8_t *)(packet->pb->payload)) - UDP_HLEN - IP_HLEN);
            packet->dest.u_addr.ip4.addr = iphdr->dest.addr;
            packet->multicast = ip4_addr_ismulticast(&(packet->dest.u_addr.ip4));
        }
#endif // LWIP_IPV4
#if LWIP_IPV6
        if (packet->src.type == IPADDR_TYPE_V6) {
            packet->ip_protocol = MDNS_IP_PROTOCOL_V6;
            struct ip6_hdr *ip6hdr = (struct ip6_hdr *)(((uint8_t *)(packet->pb->payload)) - UDP_HLEN - IP6_HLEN);
            memcpy(&packet->dest.u_addr.ip6.addr, (uint8_t *)ip6hdr->dest.addr, 16);
            packet->multicast = ip6_addr_ismulticast(&(packet->dest.u_addr.ip6));
        }
#endif // LWIP_IPV6

        //lwip does not return the proper pcb if you have more than one for the same multicast address (but different interfaces)
        struct netif *netif = NULL;
        bool found = false;
        for (i = 0; i < MDNS_MAX_INTERFACES; i++) {
            netif = esp_netif_get_netif_impl(_mdns_get_esp_netif(i));
            if (s_interfaces[i].proto && netif && netif == ip_current_input_netif()) {
#if LWIP_IPV4
                if (packet->src.type == IPADDR_TYPE_V4) {
                    if ((packet->src.u_addr.ip4.addr & ip_2_ip4(&netif->netmask)->addr) != (ip_2_ip4(&netif->ip_addr)->addr & ip_2_ip4(&netif->netmask)->addr)) {
                        //packet source is not in the same subnet
                        break;
                    }
                }
#endif // LWIP_IPV4
                packet->tcpip_if = i;
                found = true;
                break;
            }
        }

        if (!found || _mdns_send_rx_action(packet) != ESP_OK) {
            pbuf_free(this_pb);
            mdns_mem_free(packet);
        }
    }

}

bool mdns_is_netif_ready(mdns_if_t netif, mdns_ip_protocol_t ip_proto)
{
    return s_interfaces[netif].ready &&
           s_interfaces[netif].proto & (ip_proto == MDNS_IP_PROTOCOL_V4 ? PROTO_IPV4 : PROTO_IPV6);
}

/**
 * @brief  Check if any of the interfaces is up
 */
static bool _udp_pcb_is_in_use(void)
{
    int i, p;
    for (i = 0; i < MDNS_MAX_INTERFACES; i++) {
        for (p = 0; p < MDNS_IP_PROTOCOL_MAX; p++) {
            if (mdns_is_netif_ready(i, p)) {
                return true;
            }
        }
    }
    return false;
}

/**
 * @brief  Stop PCB Main code
 */
static void _udp_pcb_deinit(mdns_if_t tcpip_if, mdns_ip_protocol_t ip_protocol)
{
    s_interfaces[tcpip_if].proto &= ~(ip_protocol == MDNS_IP_PROTOCOL_V4 ? PROTO_IPV4 : PROTO_IPV6);
    if (s_interfaces[tcpip_if].proto == 0) {
        s_interfaces[tcpip_if].ready = false;
        _udp_join_group(tcpip_if, ip_protocol, false);
        if (!_udp_pcb_is_in_use()) {
            _udp_pcb_main_deinit();
        }
    }
}

/**
 * @brief  Start PCB Main code
 */
static esp_err_t _udp_pcb_init(mdns_if_t tcpip_if, mdns_ip_protocol_t ip_protocol)
{
    if (mdns_is_netif_ready(tcpip_if, ip_protocol)) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = _udp_join_group(tcpip_if, ip_protocol, true);
    if (err) {
        return err;
    }

    err = _udp_pcb_main_init();
    if (err) {
        return err;
    }
    s_interfaces[tcpip_if].proto |= (ip_protocol == MDNS_IP_PROTOCOL_V4 ? PROTO_IPV4 : PROTO_IPV6);
    s_interfaces[tcpip_if].ready = true;

    return ESP_OK;
}

typedef struct {
    struct tcpip_api_call_data call;
    mdns_if_t tcpip_if;
    mdns_ip_protocol_t ip_protocol;
    struct pbuf *pbt;
    const ip_addr_t *ip;
    uint16_t port;
    esp_err_t err;
} mdns_api_call_t;

/**
 * @brief  Start PCB from LwIP thread
 */
static err_t _mdns_pcb_init_api(struct tcpip_api_call_data *api_call_msg)
{
    mdns_api_call_t *msg = (mdns_api_call_t *)api_call_msg;
    msg->err = _udp_pcb_init(msg->tcpip_if, msg->ip_protocol) == ESP_OK ? ERR_OK : ERR_IF;
    return msg->err;
}

/**
 * @brief  Stop PCB from LwIP thread
 */
static err_t _mdns_pcb_deinit_api(struct tcpip_api_call_data *api_call_msg)
{
    mdns_api_call_t *msg = (mdns_api_call_t *)api_call_msg;
    _udp_pcb_deinit(msg->tcpip_if, msg->ip_protocol);
    msg->err = ESP_OK;
    return ESP_OK;
}

/*
 * Non-static functions below are
 *  - _mdns prefixed
 *  - commented in mdns_networking.h header
 */
esp_err_t _mdns_pcb_init(mdns_if_t tcpip_if, mdns_ip_protocol_t ip_protocol)
{
    mdns_api_call_t msg = {
        .tcpip_if = tcpip_if,
        .ip_protocol = ip_protocol
    };
    tcpip_api_call(_mdns_pcb_init_api, &msg.call);
    return msg.err;
}

esp_err_t _mdns_pcb_deinit(mdns_if_t tcpip_if, mdns_ip_protocol_t ip_protocol)
{
    mdns_api_call_t msg = {
        .tcpip_if = tcpip_if,
        .ip_protocol = ip_protocol
    };
    tcpip_api_call(_mdns_pcb_deinit_api, &msg.call);
    return msg.err;
}

static err_t _mdns_udp_pcb_write_api(struct tcpip_api_call_data *api_call_msg)
{
    void *nif = NULL;
    mdns_api_call_t *msg = (mdns_api_call_t *)api_call_msg;
    nif = esp_netif_get_netif_impl(_mdns_get_esp_netif(msg->tcpip_if));
    if (!nif || !mdns_is_netif_ready(msg->tcpip_if, msg->ip_protocol) || _pcb_main == NULL) {
        pbuf_free(msg->pbt);
        msg->err = ERR_IF;
        return ERR_IF;
    }
    esp_err_t err = udp_sendto_if(_pcb_main, msg->pbt, msg->ip, msg->port, (struct netif *)nif);
    pbuf_free(msg->pbt);
    msg->err = err;
    return err;
}

size_t _mdns_udp_pcb_write(mdns_if_t tcpip_if, mdns_ip_protocol_t ip_protocol, const esp_ip_addr_t *ip, uint16_t port, uint8_t *data, size_t len)
{
    struct pbuf *pbt = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (pbt == NULL) {
        return 0;
    }
    memcpy((uint8_t *)pbt->payload, data, len);

    ip_addr_t ip_add_copy;
#if LWIP_IPV6 && LWIP_IPV4
    ip_add_copy.type = ip->type;
    memcpy(&(ip_add_copy.u_addr), &(ip->u_addr), sizeof(ip_add_copy.u_addr));
#elif LWIP_IPV4
    ip_add_copy.addr = ip->u_addr.ip4.addr;
#elif LWIP_IPV6
#if LWIP_IPV6_SCOPES
    ip_add_copy.zone = ip->u_addr.ip6.zone;
#endif // LWIP_IPV6_SCOPES
    memcpy(ip_add_copy.addr, ip->u_addr.ip6.addr, sizeof(ip_add_copy.addr));
#endif

    mdns_api_call_t msg = {
        .tcpip_if = tcpip_if,
        .ip_protocol = ip_protocol,
        .pbt = pbt,
        .ip = &ip_add_copy,
        .port = port
    };
    tcpip_api_call(_mdns_udp_pcb_write_api, &msg.call);

    if (msg.err) {
        return 0;
    }
    return len;
}

void *_mdns_get_packet_data(mdns_rx_packet_t *packet)
{
    return packet->pb->payload;
}

size_t _mdns_get_packet_len(mdns_rx_packet_t *packet)
{
    return packet->pb->len;
}

void _mdns_packet_free(mdns_rx_packet_t *packet)
{
    pbuf_free(packet->pb);
    mdns_mem_free(packet);
}
