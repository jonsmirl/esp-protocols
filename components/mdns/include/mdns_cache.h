/**
 * @file mdns_cache.h
 * @brief mDNS name-to-address cache for Matter device reconnection
 *
 * Caches resolved mDNS instance names → IP addresses + TXT records so that
 * CHIP resolves can be answered entirely from the cache, eliminating
 * mDNS SRV/TXT/AAAA queries for operational devices.
 *
 * Three-state cache entries:
 *   FRESH  - address is good, serve it on lookup
 *   STALE  - CASE timed out, device is down, don't waste time resolving
 *   EMPTY  - no entry (first time seeing this device)
 *
 * Populated by: mDNS browse announcements (onMdnsBrowseResult),
 *               successful mDNS resolves (OnResolveDone fallback).
 * Marked stale by: CASE connection TIMEOUT.
 *
 * Thread-safe via FreeRTOS mutex.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum TXT entries per cache entry (Matter operational has ~5: SII,SAI,SAT,T,ICD) */
#define MDNS_CACHE_MAX_TXT     6
/** Maximum TXT key length (Matter keys: "SII","SAI","SAT","T","ICD" → max 3) */
#define MDNS_CACHE_TXT_KEY_MAX 4
/** Maximum TXT value length (Matter values: ms numbers up to "3600000" → max 7) */
#define MDNS_CACHE_TXT_VAL_MAX 12

/** A single TXT key-value pair stored in the cache. Self-contained (no pointers). */
typedef struct {
    char key[MDNS_CACHE_TXT_KEY_MAX];
    uint8_t value[MDNS_CACHE_TXT_VAL_MAX];
    uint8_t key_len;
    uint8_t value_len;
} mdns_cache_txt_t;

/** Cache lookup result */
typedef enum {
    MDNS_CACHE_HIT,        /**< Fresh entry found — use the address */
    MDNS_CACHE_MISS,       /**< No entry — device never seen, do real mDNS */
    MDNS_CACHE_STALE,      /**< Entry exists but CASE timed out — device is down, don't bother resolving */
} mdns_cache_result_t;

/**
 * @brief Initialize the mDNS cache
 * @param max_entries Maximum number of cache entries (e.g. 200)
 */
void mdns_cache_init(size_t max_entries);

/**
 * @brief Store or refresh an address + TXT in the cache (clears stale flag)
 * @param instance_name Matter instance name (33 chars)
 * @param addr_bytes 16-byte IPv6 address (or IPv4-mapped IPv6)
 * @param port Port number
 * @param txt Array of TXT entries (NULL to preserve existing TXT)
 * @param txt_count Number of TXT entries (0 to preserve existing TXT)
 */
void mdns_cache_put(const char *instance_name,
                    const uint8_t *addr_bytes, uint16_t port,
                    const mdns_cache_txt_t *txt, size_t txt_count);

/**
 * @brief Look up an address + TXT in the cache
 * @param instance_name Matter instance name to look up
 * @param addr_bytes Output: 16-byte address (caller provides buffer)
 * @param port Output: port number
 * @param txt_out Output: array of TXT entries (caller provides buffer, may be NULL)
 * @param txt_count_out Output: number of TXT entries returned (may be NULL)
 * @param txt_max Maximum TXT entries to return
 * @return MDNS_CACHE_HIT if fresh entry found (addr/port/txt filled in),
 *         MDNS_CACHE_STALE if device is down (don't resolve),
 *         MDNS_CACHE_MISS if never seen (do real mDNS)
 */
mdns_cache_result_t mdns_cache_get(const char *instance_name,
                                   uint8_t *addr_bytes, uint16_t *port,
                                   mdns_cache_txt_t *txt_out,
                                   size_t *txt_count_out,
                                   size_t txt_max);

/**
 * @brief Mark an entry as stale (CASE connection timed out)
 */
void mdns_cache_mark_stale(const char *instance_name);

/**
 * @brief Note a connection failure for a cached entry (LwIP routing error etc.)
 */
void mdns_cache_note_failure(const char *instance_name);

/**
 * @brief Remove a specific entry from the cache
 */
void mdns_cache_invalidate(const char *instance_name);

/**
 * @brief Remove all entries from the cache
 */
void mdns_cache_flush(void);

/**
 * @brief Get cache statistics
 */
void mdns_cache_stats(size_t *total, size_t *valid, size_t *stale,
                      size_t *hits, size_t *misses);

/**
 * @brief Store SRV record data (instance_name → hostname + port).
 *        Creates entry if not found; updates hostname/port if exists.
 *        Called directly from mDNS packet parser.
 * @return true if a new entry was created
 */
bool mdns_cache_put_srv(const char *instance_name, const char *hostname, uint16_t port);

/**
 * @brief Store address by hostname (hostname → addr).
 *        Looks up entry by hostname (from SRV), stores the address.
 *        Prefers link-local: won't overwrite link-local with non-link-local.
 * @return true if an entry was found and updated
 */
bool mdns_cache_put_addr_by_hostname(const char *hostname,
                                     const uint8_t *addr_bytes, bool is_ipv6,
                                     bool is_linklocal);

/**
 * @brief Update TXT records for an existing entry.
 *        No-op if the instance_name is not in the cache (TXT before SRV).
 */
void mdns_cache_update_txt(const char *instance_name,
                           const mdns_cache_txt_t *txt, size_t txt_count);

/**
 * @brief Check if any cache entry has a given hostname (from SRV record).
 *        Used by _mdns_browse_find_from() for A/AAAA matching.
 * @return true if at least one entry has this hostname
 */
bool mdns_cache_has_hostname(const char *hostname);

#ifdef __cplusplus
}
#endif
