/**
 * @file mdns_cache.c
 * @brief mDNS name-to-address + TXT cache implementation
 *
 * Flat array in PSRAM with two sorted index arrays for O(log n) lookup:
 *   sInstanceIndex[] - sorted by instance_name (for SRV/TXT/get/put)
 *   sHostnameIndex[] - sorted by hostname (for A/AAAA matching)
 *
 * Three-state entries:
 *   FRESH (valid && !stale) - serve on lookup
 *   STALE (valid && stale)  - CASE failed, waiting for re-announce
 *   EMPTY (!valid)          - unused slot
 *
 * Populated directly by mDNS packet parser (put_srv, put_addr_by_hostname,
 * update_txt) and by mDNS resolve fallback (mdns_cache_put).
 * 200 entries x ~176 bytes = ~35KB in PSRAM.
 */

#include "mdns_cache.h"

#include <string.h>
#include <strings.h>
#include <esp_log.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

static const char *TAG = "mdns_cache";

/* After this many ms, stale entries become fresh again so the fail_count
 * mechanism can attempt reconnection with the cached address.  This
 * prevents stale entries from being permanent dead ends. */
#define STALE_TIMEOUT_MS 30000

/* Instance name: 16 hex + '-' + 16 hex + '\0' = 34 bytes */
#define INSTANCE_NAME_SIZE 34

/* Hostname from SRV target: typically 12-char hex + '\0' */
#define HOSTNAME_SIZE 34

/* Maximum entries we support for index arrays (must be >= sMaxEntries) */
#define MAX_INDEX_ENTRIES 200

typedef struct {
    char instance_name[INSTANCE_NAME_SIZE];
    char hostname[HOSTNAME_SIZE];   /* SRV target hostname (for A/AAAA matching) */
    uint8_t addr_bytes[16];
    uint16_t port;
    uint32_t timestamp_ms;  /* last update time, used for LRU eviction */
    bool valid;
    bool stale;             /* CASE failed — waiting for device to re-announce */
    bool has_addr;          /* true after first address stored */
    bool addr_is_linklocal; /* true if stored addr is link-local IPv6 */
    uint8_t fail_count;     /* consecutive connection failures (LwIP errors) */
    bool refreshing;        /* currently forcing real mDNS to refresh NDP */
    mdns_cache_txt_t txt[MDNS_CACHE_MAX_TXT];
    uint8_t txt_count;
} mdns_cache_entry_t;

static mdns_cache_entry_t *sEntries = NULL;
static size_t sMaxEntries = 0;
static SemaphoreHandle_t sMutex = NULL;
static size_t sHits = 0;
static size_t sMisses = 0;

/* Sorted index arrays — indices into sEntries[]. Kept sorted for binary search. */
static uint16_t sInstanceIndex[MAX_INDEX_ENTRIES];  /* sorted by instance_name */
static uint16_t sHostnameIndex[MAX_INDEX_ENTRIES];  /* sorted by hostname */
static size_t sInstanceCount = 0;  /* valid entries in instance index */
static size_t sHostnameCount = 0;  /* entries with hostname set */

static uint32_t now_ms(void)
{
    return xTaskGetTickCount() * portTICK_PERIOD_MS;
}

/* ====================================================================
 * Sorted index helpers (all called with sMutex held)
 * ==================================================================== */

/**
 * Binary search sInstanceIndex for instance_name.
 * Returns index into sInstanceIndex if found, or -1.
 * Sets *insert_pos to the position where a new entry should be inserted.
 */
static int _bsearch_instance(const char *instance_name, size_t *insert_pos)
{
    size_t lo = 0, hi = sInstanceCount;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = strncasecmp(sEntries[sInstanceIndex[mid]].instance_name,
                              instance_name, INSTANCE_NAME_SIZE - 1);
        if (cmp < 0) {
            lo = mid + 1;
        } else if (cmp > 0) {
            hi = mid;
        } else {
            if (insert_pos) *insert_pos = mid;
            return (int)mid;
        }
    }
    if (insert_pos) *insert_pos = lo;
    return -1;
}

/**
 * Binary search sHostnameIndex for hostname.
 * Returns index into sHostnameIndex if found, or -1.
 * Sets *insert_pos to the position where a new entry should be inserted.
 */
static int _bsearch_hostname(const char *hostname, size_t *insert_pos)
{
    size_t lo = 0, hi = sHostnameCount;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = strncasecmp(sEntries[sHostnameIndex[mid]].hostname,
                              hostname, HOSTNAME_SIZE - 1);
        if (cmp < 0) {
            lo = mid + 1;
        } else if (cmp > 0) {
            hi = mid;
        } else {
            if (insert_pos) *insert_pos = mid;
            return (int)mid;
        }
    }
    if (insert_pos) *insert_pos = lo;
    return -1;
}

/**
 * Find entry slot by instance_name using binary search.
 * Returns slot index into sEntries[], or -1 if not found.
 */
static int _find_by_instance(const char *instance_name)
{
    int idx = _bsearch_instance(instance_name, NULL);
    if (idx >= 0) return (int)sInstanceIndex[idx];
    return -1;
}

/**
 * Find entry slot by hostname using binary search.
 * Returns slot index into sEntries[], or -1 if not found.
 */
static int _find_by_hostname(const char *hostname)
{
    int idx = _bsearch_hostname(hostname, NULL);
    if (idx >= 0) return (int)sHostnameIndex[idx];
    return -1;
}

/**
 * Insert slot into sInstanceIndex at the correct sorted position.
 */
static void _insert_instance_index(uint16_t slot)
{
    if (sInstanceCount >= MAX_INDEX_ENTRIES) return;
    size_t pos = 0;
    _bsearch_instance(sEntries[slot].instance_name, &pos);
    /* Shift right */
    if (pos < sInstanceCount) {
        memmove(&sInstanceIndex[pos + 1], &sInstanceIndex[pos],
                (sInstanceCount - pos) * sizeof(uint16_t));
    }
    sInstanceIndex[pos] = slot;
    sInstanceCount++;
}

/**
 * Insert slot into sHostnameIndex at the correct sorted position.
 */
static void _insert_hostname_index(uint16_t slot)
{
    if (sHostnameCount >= MAX_INDEX_ENTRIES) return;
    size_t pos = 0;
    _bsearch_hostname(sEntries[slot].hostname, &pos);
    /* Shift right */
    if (pos < sHostnameCount) {
        memmove(&sHostnameIndex[pos + 1], &sHostnameIndex[pos],
                (sHostnameCount - pos) * sizeof(uint16_t));
    }
    sHostnameIndex[pos] = slot;
    sHostnameCount++;
}

/**
 * Remove slot from sInstanceIndex.
 */
static void _remove_instance_index(uint16_t slot)
{
    for (size_t i = 0; i < sInstanceCount; i++) {
        if (sInstanceIndex[i] == slot) {
            if (i + 1 < sInstanceCount) {
                memmove(&sInstanceIndex[i], &sInstanceIndex[i + 1],
                        (sInstanceCount - i - 1) * sizeof(uint16_t));
            }
            sInstanceCount--;
            return;
        }
    }
}

/**
 * Remove slot from sHostnameIndex.
 */
static void _remove_hostname_index(uint16_t slot)
{
    for (size_t i = 0; i < sHostnameCount; i++) {
        if (sHostnameIndex[i] == slot) {
            if (i + 1 < sHostnameCount) {
                memmove(&sHostnameIndex[i], &sHostnameIndex[i + 1],
                        (sHostnameCount - i - 1) * sizeof(uint16_t));
            }
            sHostnameCount--;
            return;
        }
    }
}

/**
 * Clear an entry slot and remove from both indices.
 */
static void _clear_slot(int slot)
{
    _remove_instance_index((uint16_t)slot);
    if (sEntries[slot].hostname[0]) {
        _remove_hostname_index((uint16_t)slot);
    }
    sEntries[slot].valid = false;
    sEntries[slot].stale = false;
    sEntries[slot].fail_count = 0;
    sEntries[slot].refreshing = false;
    sEntries[slot].has_addr = false;
    sEntries[slot].addr_is_linklocal = false;
    sEntries[slot].txt_count = 0;
    sEntries[slot].hostname[0] = '\0';
    sEntries[slot].instance_name[0] = '\0';
}

/**
 * Find a free slot, or evict LRU (prefer stale entries for eviction).
 * If evicting, removes from both indices.
 * Returns slot index, or -1 if cache is somehow broken.
 */
static int _find_or_evict_slot(void)
{
    /* Find first free slot */
    for (size_t i = 0; i < sMaxEntries; i++) {
        if (!sEntries[i].valid) {
            return (int)i;
        }
    }

    /* No free slot — evict LRU (prefer stale) */
    int oldest_stale = -1;
    int oldest_fresh = -1;
    uint32_t oldest_stale_ts = UINT32_MAX;
    uint32_t oldest_fresh_ts = UINT32_MAX;

    for (size_t i = 0; i < sMaxEntries; i++) {
        if (sEntries[i].stale) {
            if (sEntries[i].timestamp_ms < oldest_stale_ts) {
                oldest_stale_ts = sEntries[i].timestamp_ms;
                oldest_stale = (int)i;
            }
        } else {
            if (sEntries[i].timestamp_ms < oldest_fresh_ts) {
                oldest_fresh_ts = sEntries[i].timestamp_ms;
                oldest_fresh = (int)i;
            }
        }
    }

    int slot = (oldest_stale >= 0) ? oldest_stale : oldest_fresh;
    if (slot >= 0) {
        _clear_slot(slot);
    }
    return slot;
}

/* ====================================================================
 * TXT helpers
 * ==================================================================== */

static void _store_txt(mdns_cache_entry_t *e, const mdns_cache_txt_t *txt, size_t txt_count)
{
    if (txt_count > MDNS_CACHE_MAX_TXT) {
        txt_count = MDNS_CACHE_MAX_TXT;
    }
    memcpy(e->txt, txt, txt_count * sizeof(mdns_cache_txt_t));
    e->txt_count = (uint8_t)txt_count;
}

static void _copy_txt_out(const mdns_cache_entry_t *e, mdns_cache_txt_t *txt_out,
                           size_t *txt_count_out, size_t txt_max)
{
    if (!txt_out || !txt_count_out) return;
    size_t n = e->txt_count;
    if (n > txt_max) n = txt_max;
    memcpy(txt_out, e->txt, n * sizeof(mdns_cache_txt_t));
    *txt_count_out = n;
}

/* ====================================================================
 * Public API
 * ==================================================================== */

void mdns_cache_init(size_t max_entries)
{
    if (sEntries) {
        ESP_LOGW(TAG, "Already initialized");
        return;
    }

    if (max_entries > MAX_INDEX_ENTRIES) {
        ESP_LOGW(TAG, "Clamping max_entries from %zu to %d", max_entries, MAX_INDEX_ENTRIES);
        max_entries = MAX_INDEX_ENTRIES;
    }

    sEntries = (mdns_cache_entry_t *)heap_caps_calloc(
        max_entries, sizeof(mdns_cache_entry_t), MALLOC_CAP_SPIRAM);
    if (!sEntries) {
        ESP_LOGE(TAG, "Failed to allocate %zu entries in PSRAM", max_entries);
        return;
    }

    sMutex = xSemaphoreCreateMutex();
    if (!sMutex) {
        ESP_LOGE(TAG, "Failed to create mutex");
        heap_caps_free(sEntries);
        sEntries = NULL;
        return;
    }

    sMaxEntries = max_entries;
    sInstanceCount = 0;
    sHostnameCount = 0;
    sHits = 0;
    sMisses = 0;

    ESP_LOGI(TAG, "Initialized: %zu entries (%zuKB), index arrays %zu bytes",
             max_entries, (max_entries * sizeof(mdns_cache_entry_t)) / 1024,
             2 * MAX_INDEX_ENTRIES * sizeof(uint16_t));
}

void mdns_cache_put(const char *instance_name,
                    const uint8_t *addr_bytes, uint16_t port,
                    const mdns_cache_txt_t *txt, size_t txt_count)
{
    if (!sEntries || !sMutex || !instance_name || !addr_bytes) return;

    xSemaphoreTake(sMutex, portMAX_DELAY);

    int slot = _find_by_instance(instance_name);
    if (slot >= 0) {
        /* Update existing entry */
        memcpy(sEntries[slot].addr_bytes, addr_bytes, 16);
        sEntries[slot].port = port;
        sEntries[slot].timestamp_ms = now_ms();
        sEntries[slot].fail_count = 0;
        sEntries[slot].refreshing = false;
        sEntries[slot].has_addr = true;
        /* Only overwrite TXT if caller provides it (NULL = keep existing) */
        if (txt && txt_count > 0) {
            _store_txt(&sEntries[slot], txt, txt_count);
        }
        if (sEntries[slot].stale) {
            sEntries[slot].stale = false;
            ESP_LOGD(TAG, "Refreshed (was stale): %.33s", instance_name);
        }
        xSemaphoreGive(sMutex);
        return;
    }

    /* New entry — find or evict a slot */
    slot = _find_or_evict_slot();
    if (slot < 0) {
        xSemaphoreGive(sMutex);
        ESP_LOGW(TAG, "Cache full, no eviction candidate");
        return;
    }

    strncpy(sEntries[slot].instance_name, instance_name, INSTANCE_NAME_SIZE - 1);
    sEntries[slot].instance_name[INSTANCE_NAME_SIZE - 1] = '\0';
    sEntries[slot].hostname[0] = '\0';  /* No hostname until SRV arrives */
    memcpy(sEntries[slot].addr_bytes, addr_bytes, 16);
    sEntries[slot].port = port;
    sEntries[slot].timestamp_ms = now_ms();
    sEntries[slot].valid = true;
    sEntries[slot].stale = false;
    sEntries[slot].has_addr = true;
    sEntries[slot].addr_is_linklocal = false;
    sEntries[slot].fail_count = 0;
    sEntries[slot].refreshing = false;
    if (txt && txt_count > 0) {
        _store_txt(&sEntries[slot], txt, txt_count);
    } else {
        sEntries[slot].txt_count = 0;
    }

    _insert_instance_index((uint16_t)slot);

    xSemaphoreGive(sMutex);
    ESP_LOGD(TAG, "Added[%d]: %.33s (txt=%zu)", slot, instance_name, txt_count);
}

mdns_cache_result_t mdns_cache_get(const char *instance_name,
                                   uint8_t *addr_bytes, uint16_t *port,
                                   mdns_cache_txt_t *txt_out,
                                   size_t *txt_count_out,
                                   size_t txt_max)
{
    if (!sEntries || !sMutex || !instance_name || !addr_bytes || !port) {
        return MDNS_CACHE_MISS;
    }

    xSemaphoreTake(sMutex, portMAX_DELAY);

    int slot = _find_by_instance(instance_name);
    if (slot >= 0 && sEntries[slot].valid) {
        mdns_cache_entry_t *e = &sEntries[slot];

        if (e->stale) {
            uint32_t age = now_ms() - e->timestamp_ms;
            if (age < STALE_TIMEOUT_MS) {
                sMisses++;
                xSemaphoreGive(sMutex);
                ESP_LOGD(TAG, "Stale (device down, %ums): %.33s", age, instance_name);
                return MDNS_CACHE_STALE;
            }
            e->stale = false;
            ESP_LOGD(TAG, "Stale expired, retrying: %.33s", instance_name);
        }

        /* Entry has no address yet (SRV received, AAAA not yet) */
        if (!e->has_addr) {
            sMisses++;
            xSemaphoreGive(sMutex);
            return MDNS_CACHE_MISS;
        }

        if (e->fail_count >= 2) {
            if (e->refreshing) {
                sMisses++;
                xSemaphoreGive(sMutex);
                ESP_LOGD(TAG, "Refresh (mDNS): %.33s (fail=%u)", instance_name, e->fail_count);
                return MDNS_CACHE_MISS;
            }
            size_t refreshing_count = 0;
            for (size_t j = 0; j < sMaxEntries; j++) {
                if (sEntries[j].valid && sEntries[j].refreshing) {
                    refreshing_count++;
                }
            }
            if (refreshing_count < 2) {
                e->refreshing = true;
                sMisses++;
                xSemaphoreGive(sMutex);
                ESP_LOGD(TAG, "Refresh (mDNS): %.33s (fail=%u, slot %zu/%zu)",
                         instance_name, e->fail_count, refreshing_count + 1, (size_t)2);
                return MDNS_CACHE_MISS;
            }
            ESP_LOGD(TAG, "Hit (NDP-retry): %.33s (fail=%u)", instance_name, e->fail_count);
        }

        memcpy(addr_bytes, e->addr_bytes, 16);
        *port = e->port;
        _copy_txt_out(e, txt_out, txt_count_out, txt_max);
        sHits++;
        xSemaphoreGive(sMutex);
        ESP_LOGD(TAG, "Hit: %.33s (txt=%u)", instance_name, e->txt_count);
        return MDNS_CACHE_HIT;
    }

    sMisses++;
    xSemaphoreGive(sMutex);
    return MDNS_CACHE_MISS;
}

void mdns_cache_mark_stale(const char *instance_name)
{
    if (!sEntries || !sMutex || !instance_name) return;

    xSemaphoreTake(sMutex, portMAX_DELAY);

    int slot = _find_by_instance(instance_name);
    if (slot >= 0 && sEntries[slot].valid) {
        sEntries[slot].stale = true;
        sEntries[slot].timestamp_ms = now_ms();
        sEntries[slot].fail_count = 0;
        sEntries[slot].refreshing = false;
        ESP_LOGD(TAG, "Marked stale: %.33s", instance_name);
    }

    xSemaphoreGive(sMutex);
}

void mdns_cache_note_failure(const char *instance_name)
{
    if (!sEntries || !sMutex || !instance_name) return;

    xSemaphoreTake(sMutex, portMAX_DELAY);

    int slot = _find_by_instance(instance_name);
    if (slot >= 0 && sEntries[slot].valid && !sEntries[slot].stale) {
        if (sEntries[slot].fail_count < 255) {
            sEntries[slot].fail_count++;
        }
        ESP_LOGD(TAG, "Failure noted: %.33s (count=%u)", instance_name, sEntries[slot].fail_count);
    }

    xSemaphoreGive(sMutex);
}

void mdns_cache_invalidate(const char *instance_name)
{
    if (!sEntries || !sMutex || !instance_name) return;

    xSemaphoreTake(sMutex, portMAX_DELAY);

    int slot = _find_by_instance(instance_name);
    if (slot >= 0 && sEntries[slot].valid) {
        _clear_slot(slot);
        ESP_LOGD(TAG, "Invalidated: %.33s", instance_name);
    }

    xSemaphoreGive(sMutex);
}

void mdns_cache_flush(void)
{
    if (!sEntries || !sMutex) return;

    xSemaphoreTake(sMutex, portMAX_DELAY);

    for (size_t i = 0; i < sMaxEntries; i++) {
        sEntries[i].valid = false;
        sEntries[i].stale = false;
        sEntries[i].fail_count = 0;
        sEntries[i].refreshing = false;
        sEntries[i].has_addr = false;
        sEntries[i].addr_is_linklocal = false;
        sEntries[i].txt_count = 0;
        sEntries[i].hostname[0] = '\0';
    }
    sInstanceCount = 0;
    sHostnameCount = 0;

    xSemaphoreGive(sMutex);
    ESP_LOGI(TAG, "Flushed all entries");
}

void mdns_cache_stats(size_t *total, size_t *valid, size_t *stale,
                      size_t *hits, size_t *misses)
{
    if (!total || !valid || !stale || !hits || !misses) return;

    if (!sEntries || !sMutex) {
        *total = 0;
        *valid = 0;
        *stale = 0;
        *hits = 0;
        *misses = 0;
        return;
    }

    xSemaphoreTake(sMutex, portMAX_DELAY);

    *total = sMaxEntries;
    *hits = sHits;
    *misses = sMisses;

    size_t v = 0, s = 0;
    for (size_t i = 0; i < sMaxEntries; i++) {
        if (sEntries[i].valid) {
            if (sEntries[i].stale) {
                s++;
            } else {
                v++;
            }
        }
    }
    *valid = v;
    *stale = s;

    xSemaphoreGive(sMutex);
}

/* ====================================================================
 * New functions: called directly from mDNS packet parser
 * ==================================================================== */

bool mdns_cache_put_srv(const char *instance_name, const char *hostname, uint16_t port)
{
    if (!sEntries || !sMutex || !instance_name || !hostname) return false;

    xSemaphoreTake(sMutex, portMAX_DELAY);

    int slot = _find_by_instance(instance_name);
    if (slot >= 0) {
        /* Update existing entry with SRV data */
        sEntries[slot].port = port;
        sEntries[slot].timestamp_ms = now_ms();
        sEntries[slot].fail_count = 0;
        sEntries[slot].refreshing = false;
        if (sEntries[slot].stale) {
            sEntries[slot].stale = false;
        }
        /* Update hostname if changed */
        if (strncasecmp(sEntries[slot].hostname, hostname, HOSTNAME_SIZE - 1) != 0) {
            /* Remove old hostname from index if present */
            if (sEntries[slot].hostname[0]) {
                _remove_hostname_index((uint16_t)slot);
            }
            strncpy(sEntries[slot].hostname, hostname, HOSTNAME_SIZE - 1);
            sEntries[slot].hostname[HOSTNAME_SIZE - 1] = '\0';
            _insert_hostname_index((uint16_t)slot);
        }
        xSemaphoreGive(sMutex);
        return false;  /* Not a new entry */
    }

    /* New entry */
    slot = _find_or_evict_slot();
    if (slot < 0) {
        xSemaphoreGive(sMutex);
        ESP_LOGW(TAG, "Cache full for SRV: %.33s", instance_name);
        return false;
    }

    strncpy(sEntries[slot].instance_name, instance_name, INSTANCE_NAME_SIZE - 1);
    sEntries[slot].instance_name[INSTANCE_NAME_SIZE - 1] = '\0';
    strncpy(sEntries[slot].hostname, hostname, HOSTNAME_SIZE - 1);
    sEntries[slot].hostname[HOSTNAME_SIZE - 1] = '\0';
    sEntries[slot].port = port;
    sEntries[slot].timestamp_ms = now_ms();
    sEntries[slot].valid = true;
    sEntries[slot].stale = false;
    sEntries[slot].has_addr = false;
    sEntries[slot].addr_is_linklocal = false;
    sEntries[slot].fail_count = 0;
    sEntries[slot].refreshing = false;
    sEntries[slot].txt_count = 0;
    memset(sEntries[slot].addr_bytes, 0, 16);

    _insert_instance_index((uint16_t)slot);
    _insert_hostname_index((uint16_t)slot);

    xSemaphoreGive(sMutex);
    ESP_LOGD(TAG, "SRV[%d]: %.33s -> %s:%u", slot, instance_name, hostname, port);
    return true;
}

bool mdns_cache_put_addr_by_hostname(const char *hostname,
                                     const uint8_t *addr_bytes, bool is_ipv6,
                                     bool is_linklocal)
{
    if (!sEntries || !sMutex || !hostname || !addr_bytes) return false;

    xSemaphoreTake(sMutex, portMAX_DELAY);

    int slot = _find_by_hostname(hostname);
    if (slot < 0 || !sEntries[slot].valid) {
        xSemaphoreGive(sMutex);
        return false;  /* No entry with this hostname — SRV hasn't arrived yet */
    }

    /* Link-local preference: don't overwrite link-local with non-link-local */
    if (sEntries[slot].has_addr && sEntries[slot].addr_is_linklocal && !is_linklocal) {
        xSemaphoreGive(sMutex);
        return true;  /* Entry exists, but we prefer the existing link-local addr */
    }

    if (is_ipv6) {
        memcpy(sEntries[slot].addr_bytes, addr_bytes, 16);
    } else {
        /* IPv4-mapped IPv6: ::ffff:a.b.c.d */
        memset(sEntries[slot].addr_bytes, 0, 10);
        sEntries[slot].addr_bytes[10] = 0xFF;
        sEntries[slot].addr_bytes[11] = 0xFF;
        memcpy(&sEntries[slot].addr_bytes[12], addr_bytes, 4);
    }
    sEntries[slot].has_addr = true;
    sEntries[slot].addr_is_linklocal = is_linklocal;
    sEntries[slot].timestamp_ms = now_ms();
    sEntries[slot].fail_count = 0;
    sEntries[slot].refreshing = false;
    if (sEntries[slot].stale) {
        sEntries[slot].stale = false;
    }

    xSemaphoreGive(sMutex);
    return true;
}

void mdns_cache_update_txt(const char *instance_name,
                           const mdns_cache_txt_t *txt, size_t txt_count)
{
    if (!sEntries || !sMutex || !instance_name || !txt || txt_count == 0) return;

    xSemaphoreTake(sMutex, portMAX_DELAY);

    int slot = _find_by_instance(instance_name);
    if (slot >= 0 && sEntries[slot].valid) {
        _store_txt(&sEntries[slot], txt, txt_count);
        sEntries[slot].timestamp_ms = now_ms();
    }
    /* If not found, silently ignore — TXT arrived before SRV */

    xSemaphoreGive(sMutex);
}

bool mdns_cache_has_hostname(const char *hostname)
{
    if (!sEntries || !sMutex || !hostname) return false;

    xSemaphoreTake(sMutex, portMAX_DELAY);

    int slot = _find_by_hostname(hostname);
    bool found = (slot >= 0 && sEntries[slot].valid);

    xSemaphoreGive(sMutex);
    return found;
}
