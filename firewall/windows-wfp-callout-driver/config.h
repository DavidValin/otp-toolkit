#ifndef OTP_FW_CONFIG_H
#define OTP_FW_CONFIG_H

#include "common.h"
#include "keychain.h" /* MAX_NAME_LENGTH */

#include <stddef.h>

typedef struct
{
  char contact[MAX_NAME_LENGTH];
  char host[OTP_FW_HOST_LEN];       /* raw text from the config file: literal IP or hostname */
  char resolved_ip[OTP_FW_IPSTR_LEN]; /* "" until resolved */
} FwConfigEntry;

typedef struct
{
  FwConfigEntry *entries;
  int count;
  int capacity;
} FwConfig;

void fwconfig_init(FwConfig *cfg);
void fwconfig_free(FwConfig *cfg);

/* Parses `path` ("contact ip-or-host [ip-or-host...]" per line, '#'
 * comments, blank lines ignored) into `cfg`, replacing any prior content.
 * Returns 0 on success (including "file does not exist yet", which loads
 * an empty config), -1 on a real error. */
int fwconfig_load(const char *path, FwConfig *cfg);

/* Re-resolves every entry's `host` to `resolved_ip` (literal IPs are used
 * directly; hostnames go through getaddrinfo()). Best-effort: an entry
 * that fails to resolve keeps its previous resolved_ip (or stays "" if it
 * never resolved), and a warning is printed to stderr - this must never
 * abort the whole config reload over one bad hostname. */
void fwconfig_resolve(FwConfig *cfg);

/* First contact (in file order) whose resolved_ip matches `ip_str`, or
 * NULL if none. */
const char *fwconfig_contact_for_ip(const FwConfig *cfg, const char *ip_str);

/* Writes the set of unique resolved IPs, one per line, into `out`
 * (NUL-terminated). Returns the number of bytes written (excluding the
 * NUL), or -1 if `out_size` was too small. */
int fwconfig_candidate_ips(const FwConfig *cfg, char *out, size_t out_size);

#endif /* OTP_FW_CONFIG_H */
