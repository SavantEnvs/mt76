// SPDX-License-Identifier: ISC
/*
 * Link stubs for the mt7615 targets: functions the compiled mt7615/mac.c, mt7615/mcu.c, mcu.c, mac80211.c, tx.c and scan.c
 * reference that live in files this target does not build (mt76_connac_mcu.c, mt76_connac_mac.c, channel.c, dma.c) or in
 * mac80211/cfg80211. Generated from the linker's undefined-symbol list, then checked against a
 * call graph of the linked target from LLVMFuzzerTestOneInput (direct calls plus every function
 * whose address is taken). The scan code and radiotap decoders are the real upstream files, not
 * stubs. The only stubs that graph reaches sit behind state the harness never creates (no TX
 * token in the IDR, no station wcid, WED inactive, no background radar phy): mt7615_txwi_free (TX-free tokens).
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

STUB(mt76_abort_roc)
STUB(mt76_connac_mcu_add_nested_tlv)
STUB(__mt76_connac_mcu_alloc_sta_req)
STUB(mt76_connac_mcu_alloc_wtbl_req)
STUB(mt76_connac_mcu_bss_basic_tlv)
STUB(mt76_connac_mcu_bss_ext_tlv)
STUB(mt76_connac_mcu_bss_omac_tlv)
STUB(mt76_connac_mcu_init_download)
STUB(mt76_connac_mcu_patch_sem_ctrl)
STUB(mt76_connac_mcu_rdd_cmd)
STUB(mt76_connac_mcu_set_pm)
STUB(mt76_connac_mcu_sta_ba)
STUB(mt76_connac_mcu_sta_basic_tlv)
STUB(mt76_connac_mcu_sta_ba_tlv)
STUB(mt76_connac_mcu_sta_cmd)
STUB(mt76_connac_mcu_start_firmware)
STUB(mt76_connac_mcu_start_patch)
STUB(mt76_connac_mcu_sta_tlv)
STUB(mt76_connac_mcu_sta_update_hdr_trans)
STUB(mt76_connac_mcu_uni_add_bss)
STUB(mt76_connac_mcu_uni_add_dev)
STUB(mt76_connac_mcu_wtbl_ba_tlv)
STUB(mt76_connac_mcu_wtbl_generic_tlv)
STUB(mt76_connac_mcu_wtbl_hdr_trans_tlv)
STUB(mt76_connac_mcu_wtbl_ht_tlv)
STUB(mt76_connac_mcu_wtbl_update_hdr_trans)
STUB(mt76_connac_pm_dequeue_skbs)
STUB(mt76_connac_pm_wake)
STUB(mt76_connac_power_save_sched)
STUB(mt76_connac_txp_skb_unmap)
STUB(mt76_get_rate_power_limits)
STUB(mt76_put_txwi)
STUB(mt76_roc_complete)
STUB(mt76_roc_complete_work)
STUB(ieee80211_probereq_get)
STUB(mt76_get_vif_phy_link)
STUB(mt76_phy_csa_active)
STUB(mt76_put_vif_phy_link)
