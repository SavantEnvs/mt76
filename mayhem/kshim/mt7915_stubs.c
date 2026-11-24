// SPDX-License-Identifier: ISC
/*
 * Link stubs for the mt7915 targets: functions the compiled mt7915/mac.c, mt7915/mcu.c, mt76_connac_mac.c, mcu.c, mac80211.c, tx.c and scan.c
 * reference that live in files this target does not build (mt76_connac_mcu.c, mt7915/main.c, mt7915/init.c, mt7915/dma.c, mt7915/debugfs.c, channel.c) or in
 * mac80211/cfg80211. Generated from the linker's undefined-symbol list, then checked against a
 * call graph of the linked target from LLVMFuzzerTestOneInput (direct calls plus every function
 * whose address is taken). The scan code and radiotap decoders are the real upstream files, not
 * stubs. The only stubs that graph reaches sit behind state the harness never creates (no TX
 * token in the IDR, no station wcid, WED inactive, no background radar phy): mt76_connac2_txwi_free (TX-free tokens), mt76_connac2_mac_fill_txs (a station wcid), mt7915_wed_check_ppe (WED) and mt7915_mcu_rx_radar_detected (MT_RDD_IDX_BACKGROUND with rdd2_phy set).
 * Reaching any stub aborts with its name, except the two debugfs log sinks (below).
 * This file includes no driver header on purpose, so the stubs' (void) signatures never meet
 * the real prototypes.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STUB(name) \
	void name(void) { fprintf(stderr, "kshim: %s is not part of this target\n", #name); abort(); }

/*
 * mt7915/debugfs.c:mt7915_debugfs_rx_log() as it runs with no fwlog relay open (relay_fwlog is
 * NULL until a user opens the debugfs file): it reads the 4-byte binary-log magic at the start of
 * the firmware log payload, unconditionally, as the real function does.
 */
/* mt7915/debugfs.c:mt7915_debugfs_rx_fw_monitor() with no fwlog relay open: returns before reading. */
void mt7915_debugfs_rx_fw_monitor(void *dev, const void *data, int len) { (void)dev; (void)data; (void)len; }

#define FW_BIN_LOG_MAGIC 0x44e98caf
bool mt7915_debugfs_rx_log(void *dev, const void *data, int len)
{
	uint32_t magic;

	(void)dev; (void)len;
	memcpy(&magic, data, sizeof(magic));	/* get_unaligned_le32(data) */
	return magic == FW_BIN_LOG_MAGIC;
}

STUB(__mt76_connac_mcu_alloc_sta_req)
STUB(__mt7915_get_tsf)
STUB(cfg80211_background_radar_event)
STUB(cfg80211_bss_iter)
STUB(cfg80211_chandef_valid)
STUB(dev_is_pci)
STUB(ieee80211_bss_get_elem)
STUB(ieee80211_get_fils_discovery_tmpl)
STUB(ieee80211_get_unsol_bcast_probe_resp_tmpl)
STUB(ieee80211_refresh_tx_agg_session_timer)
STUB(ieee80211_start_tx_ba_session)
STUB(ieee80211_vif_to_wdev)
STUB(mt76_abort_roc)
STUB(mt76_connac2_load_patch)
STUB(mt76_connac2_load_ram)
STUB(mt76_connac2_mcu_fill_message)
STUB(mt76_connac_get_he_phy_cap)
STUB(mt76_connac_get_phy_mode)
STUB(mt76_connac_mcu_add_nested_tlv)
STUB(mt76_connac_mcu_alloc_wtbl_req)
STUB(mt76_connac_mcu_bss_basic_tlv)
STUB(mt76_connac_mcu_bss_ext_tlv)
STUB(mt76_connac_mcu_bss_omac_tlv)
STUB(mt76_connac_mcu_del_wtbl_all)
STUB(mt76_connac_mcu_patch_sem_ctrl)
STUB(mt76_connac_mcu_rdd_cmd)
STUB(mt76_connac_mcu_restart)
STUB(mt76_connac_mcu_sta_ba)
STUB(mt76_connac_mcu_sta_basic_tlv)
STUB(mt76_connac_mcu_sta_uapsd)
STUB(mt76_connac_mcu_sta_wed_update)
STUB(mt76_connac_mcu_wtbl_generic_tlv)
STUB(mt76_connac_mcu_wtbl_hdr_trans_tlv)
STUB(mt76_connac_mcu_wtbl_ht_tlv)
STUB(mt76_connac_mcu_wtbl_smps_tlv)
STUB(mt76_get_rate_power_limits)
STUB(mt76_put_txwi)
STUB(mt76_roc_complete)
STUB(mt76_roc_complete_work)
STUB(mt76_set_irq_mask)
STUB(mt7915_dma_reset)
STUB(mt7915_dma_start)
STUB(mt7915_dual_hif_set_irq_mask)
STUB(mt7915_eeprom_get_power_delta)
STUB(mt7915_eeprom_get_target_power)
STUB(mt7915_global_wcid_init)
STUB(mt7915_init_txpower)
STUB(mt7915_mac_init)
STUB(mt7915_memcpy_fromio)
STUB(mt7915_run)
STUB(mt7915_sku_group_len)
STUB(mt7915_txbf_init)
STUB(mt7915_vow_sta_bss_grp)
STUB(ieee80211_probereq_get)
STUB(mt76_get_vif_phy_link)
STUB(mt76_phy_csa_active)
STUB(mt76_put_vif_phy_link)
