#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* inet_pton()/inet_ntop()/getaddrinfo()/struct sockaddr_in{,6} all come
 * from <ws2tcpip.h>/<winsock2.h> on Windows instead of POSIX's
 * <arpa/inet.h>/<netdb.h>/<sys/socket.h> - same functions, same
 * semantics, but Windows additionally requires WSAStartup() to have
 * been called once before any of them are used (WSACleanup() on the way
 * out); unlike everything else in this file, that's a real runtime
 * requirement, not just a header swap - the Windows service's own
 * startup (see ../windows-wfp-callout-driver/Service/) does it once,
 * before touching config.c at all, rather than this file managing its
 * own Winsock lifetime. */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

void fwconfig_init(FwConfig *cfg)
{
  cfg->entries = NULL;
  cfg->count = 0;
  cfg->capacity = 0;
}

void fwconfig_free(FwConfig *cfg)
{
  free(cfg->entries);
  cfg->entries = NULL;
  cfg->count = 0;
  cfg->capacity = 0;
}

static int fwconfig_append(FwConfig *cfg, const char *contact, const char *host)
{
  if (cfg->count >= OTP_FW_MAX_CONFIG_ENTRIES)
  {
    fprintf(stderr, "Error: firewall.config exceeds %d entries, ignoring the rest\n", OTP_FW_MAX_CONFIG_ENTRIES);
    return -1;
  }
  if (cfg->count == cfg->capacity)
  {
    int new_cap = cfg->capacity ? cfg->capacity * 2 : 64;
    FwConfigEntry *grown = realloc(cfg->entries, (size_t)new_cap * sizeof(FwConfigEntry));
    if (!grown)
    {
      fprintf(stderr, "Error: out of memory loading firewall.config\n");
      return -1;
    }
    cfg->entries = grown;
    cfg->capacity = new_cap;
  }
  FwConfigEntry *e = &cfg->entries[cfg->count];
  memset(e, 0, sizeof(*e));
  snprintf(e->contact, sizeof(e->contact), "%s", contact);
  snprintf(e->host, sizeof(e->host), "%s", host);
  cfg->count++;
  return 0;
}

/* Copies resolved_ip forward from `old` into `cfg`'s entries wherever the
 * (contact, host) pair is unchanged, so a config reload doesn't throw
 * away a perfectly good address just because this run's re-resolve
 * happens to be re-parsing the file - fwconfig_resolve()'s "keep the
 * previous address on a transient failure" fallback only has anything to
 * fall back to if a reload didn't already erase it first. */
static void carry_forward_resolved_ips(FwConfig *cfg, const FwConfig *old)
{
  for (int i = 0; i < cfg->count; i++)
  {
    for (int j = 0; j < old->count; j++)
    {
      if (strcmp(cfg->entries[i].contact, old->entries[j].contact) == 0 &&
         strcmp(cfg->entries[i].host, old->entries[j].host) == 0)
      {
        snprintf(cfg->entries[i].resolved_ip, sizeof(cfg->entries[i].resolved_ip),
                "%s", old->entries[j].resolved_ip);
        break;
      }
    }
  }
}

/* Shared cleanup for both post-fopen() failure paths below (a partial
 * new parse that hit the entry cap, or a read error): discard whatever
 * of the new parse exists in `cfg` and restore `old` into it, so a
 * mid-load failure never leaves `cfg` half-built or empty. Doesn't
 * itself return - callers still need their own `return -1;`, this just
 * keeps the four-line sequence from drifting between the two call
 * sites. */
static void restore_old_config(FILE *f, FwConfig *cfg, FwConfig *old)
{
  fclose(f);
  fwconfig_free(cfg);
  *cfg = *old;
}

int fwconfig_load(const char *path, FwConfig *cfg)
{
  FwConfig old = *cfg; /* takes ownership of cfg's previous entries array */
  fwconfig_init(cfg);  /* cfg starts fresh; `old` still owns the old memory */

  FILE *f = fopen(path, "r");
  if (!f)
  {
    if (errno == ENOENT)
    {
      /* No config yet (or deliberately removed): empty is the correct,
       * intentional result here, not a failure to fall back from. */
      fwconfig_free(&old);
      return 0;
    }
    /* Any other fopen() failure (EACCES, EMFILE, a transient EIO, ...)
     * must not silently wipe every configured contact just because one
     * reload attempt hit a hiccup - restore the last-known-good config
     * instead of leaving `cfg` empty, the same "keep going on a
     * transient failure" principle fwconfig_resolve() already applies
     * to individual hostname lookups. */
    fprintf(stderr, "Error: cannot open '%s': %s - keeping the previous configuration\n",
           path, strerror(errno));
    *cfg = old;
    return -1;
  }

  char line[1024];
  while (fgets(line, sizeof(line), f))
  {
    char *hash = strchr(line, '#');
    if (hash)
      *hash = '\0';

    char *save = NULL;
    char *contact = strtok_r(line, " \t\r\n", &save);
    if (!contact)
      continue;

    char *host;
    int any = 0;
    while ((host = strtok_r(NULL, " \t\r\n", &save)) != NULL)
    {
      if (fwconfig_append(cfg, contact, host) != 0)
      {
        /* Same principle: discard the partial new parse and restore the
         * previous good config rather than leaving `cfg` half-built. */
        restore_old_config(f, cfg, &old);
        return -1;
      }
      any = 1;
    }
    if (!any)
      fprintf(stderr, "Warning: firewall.config: contact '%s' has no ip/host entries, ignoring\n", contact);
  }

  /* fgets() returns NULL both at a clean EOF and on a read error (e.g.
   * `path` names a directory: fopen() succeeds on Linux even though
   * nothing there can actually be read, so the failure only surfaces
   * here), and the two are not interchangeable - without this check, a
   * mid-read failure looks identical to "successfully parsed an empty
   * file" and would wipe the config exactly like the on-open failure
   * path above is trying to avoid. */
  if (ferror(f))
  {
    fprintf(stderr, "Error: failed reading '%s': %s - keeping the previous configuration\n",
           path, strerror(errno));
    restore_old_config(f, cfg, &old);
    return -1;
  }
  fclose(f);

  carry_forward_resolved_ips(cfg, &old);
  fwconfig_free(&old);
  return 0;
}

static int resolve_one(const char *host, char *out, size_t out_size)
{
  struct in_addr v4;
  if (inet_pton(AF_INET, host, &v4) == 1)
  {
    if (!inet_ntop(AF_INET, &v4, out, out_size))
      return -1;
    return 0;
  }
  struct in6_addr v6;
  if (inet_pton(AF_INET6, host, &v6) == 1)
  {
    if (!inet_ntop(AF_INET6, &v6, out, out_size))
      return -1;
    return 0;
  }

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  struct addrinfo *res = NULL;
  if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res)
    return -1;

  int rc = -1;
  if (res->ai_family == AF_INET)
  {
    struct sockaddr_in *sin = (struct sockaddr_in *)(void *)res->ai_addr;
    if (inet_ntop(AF_INET, &sin->sin_addr, out, out_size))
      rc = 0;
  }
  else if (res->ai_family == AF_INET6)
  {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(void *)res->ai_addr;
    if (inet_ntop(AF_INET6, &sin6->sin6_addr, out, out_size))
      rc = 0;
  }
  freeaddrinfo(res);
  return rc;
}

void fwconfig_resolve(FwConfig *cfg)
{
  for (int i = 0; i < cfg->count; i++)
  {
    FwConfigEntry *e = &cfg->entries[i];
    char resolved[OTP_FW_IPSTR_LEN];
    if (resolve_one(e->host, resolved, sizeof(resolved)) == 0)
    {
      snprintf(e->resolved_ip, sizeof(e->resolved_ip), "%s", resolved);
    }
    else
    {
      fprintf(stderr, "Warning: could not resolve '%s' for contact '%s'%s\n",
              e->host, e->contact, e->resolved_ip[0] ? " (keeping previous address)" : "");
    }
  }
}

const char *fwconfig_contact_for_ip(const FwConfig *cfg, const char *ip_str)
{
  for (int i = 0; i < cfg->count; i++)
  {
    if (cfg->entries[i].resolved_ip[0] && strcmp(cfg->entries[i].resolved_ip, ip_str) == 0)
      return cfg->entries[i].contact;
  }
  return NULL;
}

int fwconfig_candidate_ips(const FwConfig *cfg, char *out, size_t out_size)
{
  size_t pos = 0;
  for (int i = 0; i < cfg->count; i++)
  {
    const char *ip = cfg->entries[i].resolved_ip;
    if (!ip[0])
      continue;

    int dup = 0;
    for (int j = 0; j < i; j++)
    {
      if (cfg->entries[j].resolved_ip[0] && strcmp(cfg->entries[j].resolved_ip, ip) == 0)
      {
        dup = 1;
        break;
      }
    }
    if (dup)
      continue;

    size_t len = strlen(ip);
    if (pos + len + 1 >= out_size)
      return -1;
    memcpy(out + pos, ip, len);
    pos += len;
    out[pos++] = '\n';
  }
  out[pos] = '\0';
  return (int)pos;
}
