// SPDX-License-Identifier: ISC
/*
 * Link stubs for the mt7996 targets: functions the compiled mt7996/mac.c, mt7996/mcu.c, mt76_connac3_mac.c, mcu.c, mac80211.c, tx.c and scan.c
 * reference that live in files this target does not build (mt76_connac_mcu.c, mt76_connac_mac.c, mt7996/main.c, mt7996/init.c, mt7996/dma.c, mt7996/debugfs.c, channel.c) or in
 * mac80211/cfg80211. Generated from the linker's undefined-symbol list, then checked against a
 * call graph of the linked target from LLVMFuzzerTestOneInput (direct calls plus every function
 * whose address is taken). The scan code and radiotap decoders are the real upstream files, not
 * stubs. The only stubs that graph reaches sit behind state the harness never creates (no TX
 * token in the IDR, no station wcid, WED inactive, no background radar phy): mt7996_txwi_free (TX-free tokens), mt7996_mac_add_txs_skb (a station wcid with WED), mt7996_wed_check_ppe (WED) and mt7996_mcu_rx_radar_detected (MT_RDD_IDX_BACKGROUND with rdd2_phy set).
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
 * mt7996/debugfs.c:mt7996_debugfs_rx_log() as it runs with no fwlog relay open (relay_fwlog is
 * NULL until a user opens the debugfs file): it reads the 4-byte binary-log magic at the start of
 * the firmware log payload, unconditionally, as the real function does.
 */
/* mt7996/debugfs.c:mt7996_debugfs_rx_fw_monitor() with no fwlog relay open: returns before reading. */
void mt7996_debugfs_rx_fw_monitor(void *dev, const void *data, int len) { (void)dev; (void)data; (void)len; }

#define FW_BIN_LOG_MAGIC 0x44d9c99a
bool mt7996_debugfs_rx_log(void *dev, const void *data, int len)
{
	uint32_t magic;

	(void)dev; (void)len;
	memcpy(&magic, data, sizeof(magic));	/* get_unaligned_le32(data) */
	return magic == FW_BIN_LOG_MAGIC;
}

STUB(__mt76_connac_mcu_alloc_sta_req)
STUB(cfg80211_background_radar_event)
STUB(cfg80211_chandef_valid)
STUB(cfg80211_dscp_to_up)
STUB(ieee80211_get_fils_discovery_tmpl)
STUB(ieee80211_get_unsol_bcast_probe_resp_tmpl)
STUB(ieee80211_qos_char_direction)
STUB(mt76_abort_roc)
STUB(mt76_connac2_fw_check)
STUB(mt76_connac2_patch_check)
STUB(mt76_connac_get_eht_phy_cap)
STUB(mt76_connac_get_he_phy_cap)
STUB(mt76_connac_get_phy_mode)
STUB(mt76_connac_get_phy_mode_ext)
STUB(mt76_connac_mcu_add_nested_tlv)
STUB(mt76_connac_mcu_init_download)
STUB(mt76_connac_mcu_patch_sem_ctrl)
STUB(mt76_connac_mcu_sta_basic_tlv)
STUB(mt76_connac_mcu_sta_uapsd)
STUB(mt76_connac_mcu_start_firmware)
STUB(mt76_connac_mcu_start_patch)
STUB(mt76_get_rate_power_limits)
STUB(mt76_roc_complete)
STUB(mt76_roc_complete_work)
STUB(mt7996_mac_sta_links)
STUB(__mt7996_get_tsf)
STUB(build_skb)
STUB(dev_is_pci)
STUB(ieee80211_iterate_stations_atomic)
STUB(ieee80211_refresh_tx_agg_session_timer)
STUB(ieee80211_start_tx_ba_session)
STUB(ieee80211_vif_to_wdev)
STUB(mt76_connac_txp_skb_unmap)
STUB(mt76_put_rxwi)
STUB(mt76_put_txwi)
STUB(mt76_set_irq_mask)
STUB(mt7996_dma_reset)
STUB(mt7996_dma_start)
STUB(mt7996_dual_hif_set_irq_mask)
STUB(mt7996_global_wcid_init)
STUB(mt7996_init_txpower)
STUB(mt7996_mac_init)
STUB(mt7996_mac_sta_remove_link)
STUB(mt7996_memcpy_fromio)
STUB(mt7996_rro_hw_init)
STUB(mt7996_run)
STUB(mt7996_txbf_init)
STUB(ieee80211_probereq_get)
STUB(mt76_get_vif_phy_link)
STUB(mt76_phy_csa_active)
STUB(mt76_put_vif_phy_link)
