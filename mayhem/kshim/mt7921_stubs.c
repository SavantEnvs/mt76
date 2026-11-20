// SPDX-License-Identifier: ISC
/*
 * Link stubs for the mt7921 targets: functions the compiled mt7921/mac.c, mt7921/mcu.c, mt792x_mac.c, mt76_connac_mac.c, mcu.c, mac80211.c, tx.c and scan.c
 * reference that live in files this target does not build (mt76_connac_mcu.c, mt792x_core.c, mt7921/main.c, mt7921/init.c, mt7921/regd.c, channel.c) or in
 * mac80211/cfg80211. Generated from the linker's undefined-symbol list, then checked against a
 * call graph of the linked target from LLVMFuzzerTestOneInput (direct calls plus every function
 * whose address is taken). The scan code and radiotap decoders are the real upstream files, not
 * stubs. The only stubs that graph reaches sit behind state the harness never creates (no TX
 * token in the IDR, no station wcid, WED inactive, no background radar phy): mt76_connac2_txwi_free (TX-free tokens) and mt76_connac2_mac_fill_txs (a station wcid).
 * Reaching any stub aborts with its name, except mt76_connac_mcu_coredump_event (below).
 * This file includes no driver header on purpose, so the stubs' (void) signatures never meet
 * the real prototypes.
 */
#include <stdio.h>
#include <stdlib.h>

#define STUB(name) \
	void name(void) { fprintf(stderr, "kshim: %s is not part of this target\n", #name); abort(); }

/*
 * Firmware coredump fragments (MCU_EVENT_COREDUMP) are appended to a devcoredump buffer by
 * mt76_connac_mcu.c, which this target does not build; the caller frees the skb, so dropping the
 * fragment here keeps the event path running without a fake crash.
 */
void mt76_connac_mcu_coredump_event(void *dev, void *skb, void *coredump) { (void)dev; (void)skb; (void)coredump; }

STUB(ieee80211_refresh_tx_agg_session_timer)
STUB(ieee80211_start_tx_ba_session)
STUB(mt76_abort_roc)
STUB(mt76_connac2_fw_check)
STUB(mt76_connac_mcu_chip_config)
STUB(mt76_connac_mcu_sta_ba)
STUB(mt76_connac_mcu_sta_cmd)
STUB(mt76_find_power_limits_node)
STUB(mt76_put_txwi)
STUB(mt76_roc_complete)
STUB(mt76_roc_complete_work)
STUB(mt7921_regd_change)
STUB(mt7921_regd_clc_supported)
STUB(mt7921_regd_init)
STUB(mt7921_set_stream_he_caps)
STUB(mt792x_load_firmware)
STUB(mt792x_mcu_drv_pmctrl)
STUB(ieee80211_probereq_get)
STUB(mt76_get_vif_phy_link)
STUB(mt76_phy_csa_active)
STUB(mt76_put_vif_phy_link)
