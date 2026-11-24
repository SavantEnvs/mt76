// SPDX-License-Identifier: ISC
/*
 * Link stubs for the mt76-connac2-fw-load target: functions the compiled mt76_connac_mcu.c, mcu.c
 * and util.c reference that live in files this target does not build (mac80211.c, the power-limit
 * code in eeprom.c) or in mac80211/cfg80211. Generated from the linker's undefined-symbol list;
 * the firmware loader reaches none of them. Reaching any stub aborts with its name.
 * This file includes no driver header on purpose, so the stubs' (void) signatures never meet
 * the real prototypes.
 */
#include <stdio.h>
#include <stdlib.h>

#define STUB(name) \
	void name(void) { fprintf(stderr, "kshim: %s is not part of this target\n", #name); abort(); }

STUB(ieee80211_get_eht_iftype_cap)
STUB(ieee80211_get_he_iftype_cap)
STUB(mt76_connac_set_txpower_cur)
STUB(mt76_get_rate_power_limits)
STUB(mt76_get_sar_power)
