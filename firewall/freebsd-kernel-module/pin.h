#ifndef OTP_FW_PIN_H
#define OTP_FW_PIN_H

#include "common.h"
#include "keychain.h" /* MAX_NAME_LENGTH */

/* Not thread-safe: the daemon runs a single NFQUEUE processing loop
 * (see otp_firewalld.c), so no locking is needed here. */

typedef struct
{
  char ip[OTP_FW_IPSTR_LEN];
  char contact[MAX_NAME_LENGTH];
} PinEntry;

typedef struct
{
  PinEntry entries[OTP_FW_MAX_PINS];
  int count;
} PinTable;

void pin_init(PinTable *t);

/* NULL if `ip` is not pinned. */
const char *pin_lookup(const PinTable *t, const char *ip);

/* Pins `ip` to `contact` (upsert). 0 on success, -1 if the table is full. */
int pin_set(PinTable *t, const char *ip, const char *contact);

/* Removes every pin bound to `contact` (e.g. on contact removal or a
 * firewall.config change that reassigns that IP). */
void pin_clear_contact(PinTable *t, const char *contact);

/* Removes the pin for one specific IP, if any (e.g. its firewall.config
 * mapping changed to a different contact). */
void pin_clear_ip(PinTable *t, const char *ip);

#endif /* OTP_FW_PIN_H */
