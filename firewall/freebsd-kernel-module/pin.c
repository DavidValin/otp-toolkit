#include "pin.h"

#include <string.h>

void pin_init(PinTable *t)
{
  t->count = 0;
}

const char *pin_lookup(const PinTable *t, const char *ip)
{
  for (int i = 0; i < t->count; i++)
  {
    if (strcmp(t->entries[i].ip, ip) == 0)
      return t->entries[i].contact;
  }
  return NULL;
}

int pin_set(PinTable *t, const char *ip, const char *contact)
{
  for (int i = 0; i < t->count; i++)
  {
    if (strcmp(t->entries[i].ip, ip) == 0)
    {
      snprintf(t->entries[i].contact, sizeof(t->entries[i].contact), "%s", contact);
      return 0;
    }
  }
  if (t->count >= OTP_FW_MAX_PINS)
    return -1;
  snprintf(t->entries[t->count].ip, sizeof(t->entries[t->count].ip), "%s", ip);
  snprintf(t->entries[t->count].contact, sizeof(t->entries[t->count].contact), "%s", contact);
  t->count++;
  return 0;
}

void pin_clear_contact(PinTable *t, const char *contact)
{
  int w = 0;
  for (int r = 0; r < t->count; r++)
  {
    if (strcmp(t->entries[r].contact, contact) == 0)
      continue;
    if (w != r)
      t->entries[w] = t->entries[r];
    w++;
  }
  t->count = w;
}

void pin_clear_ip(PinTable *t, const char *ip)
{
  for (int i = 0; i < t->count; i++)
  {
    if (strcmp(t->entries[i].ip, ip) == 0)
    {
      t->entries[i] = t->entries[t->count - 1];
      t->count--;
      return;
    }
  }
}
