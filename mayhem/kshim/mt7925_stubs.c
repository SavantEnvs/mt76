// SPDX-License-Identifier: ISC
/*
 * Link stubs for the mt7925 targets: functions the compiled mt7925/mac.c, mt7925/mcu.c, mt7925/p2p.c,
 * mt792x_mac.c, mt76_connac_mac.c, mt76_connac3_mac.c, mcu.c, mac80211.c, tx.c and scan.c reference
 * that live in files this target does not build (mt76_connac_mcu.c, mt792x_core.c, mt7925/main.c,
 * mt7925/init.c, mt7925/regd.c, mt7925/nan.c, channel.c) or in mac80211/cfg80211. Generated from the
 * linker's undefined-symbol list. The radiotap decoders and the P2P RX filter are the real upstream
 * files, not stubs. Reaching any stub aborts with its name, except the two event sinks below.
 * This file includes no driver header on purpose, so the stubs' (void) signatures never meet
 * the real prototypes.
 */
#include <stdio.h>
#include <stdlib.h>

#define STUB(name) \
	void name(void) { fprintf(stderr, "kshim: %s is not part of this target\n", #name); abort(); }

/*
 * Firmware coredump fragments (MCU_UNI_EVENT_COREDUMP) are appended to a devcoredump buffer by
 * mt76_connac_mcu.c, which this target does not build; the caller frees the skb, so dropping the
 * fragment here keeps the event path running without a fake crash.
 */
void mt76_connac_mcu_coredump_event(void *dev, void *skb, void *coredump) { (void)dev; (void)skb; (void)coredump; }

/*
 * MCU_UNI_EVENT_NAN is handled by mt7925/nan.c, which does not build against the shim yet (it needs
 * the cfg80211 NAN API: struct cfg80211_nan_conf, ieee80211_nan_sched_cfg, vif->txq_mgmt).
 * The caller (mt7925_mcu_uni_rx_unsolicited_event) frees the skb, so the event is dropped here.
 */
void mt7925_nan_mcu_event(void *dev, void *skb) { (void)dev; (void)skb; }

STUB(__mt76_connac_mcu_alloc_sta_req)
STUB(cfg80211_chandef_primary)
STUB(cfg80211_rx_mgmt_khz)
STUB(ieee80211_get_eht_iftype_cap)
STUB(ieee80211_get_he_6ghz_capa)
STUB(ieee80211_get_he_iftype_cap)
STUB(ieee80211_probereq_get)
STUB(ieee80211_refresh_tx_agg_session_timer)
STUB(ieee80211_start_tx_ba_session)
STUB(ieee80211_vif_to_wdev)
STUB(mt76_abort_roc)
STUB(mt76_connac2_fw_check)
STUB(mt76_connac_get_ch_power)
STUB(mt76_connac_get_he_phy_cap)
STUB(mt76_connac_get_phy_mode)
STUB(mt76_connac_get_phy_mode_v2)
STUB(mt76_connac_mcu_add_nested_tlv)
STUB(mt76_connac_mcu_build_rnr_scan_param)
STUB(mt76_connac_mcu_sta_basic_tlv)
STUB(mt76_connac_mcu_sta_he_tlv_v2)
STUB(mt76_connac_mcu_sta_uapsd)
STUB(mt76_get_rate_power_limits)
STUB(mt76_get_vif_phy_link)
STUB(mt76_phy_csa_active)
STUB(mt76_put_txwi)
STUB(mt76_put_vif_phy_link)
STUB(mt76_roc_complete)
STUB(mt76_roc_complete_work)
STUB(mt7925_regd_change)
STUB(mt7925_regd_clc_supported)
STUB(mt7925_regd_init)
STUB(mt7925_set_stream_he_eht_caps)
STUB(mt792x_load_firmware)
STUB(mt792x_mcu_drv_pmctrl)
STUB(nl80211_chan_width_to_mhz)
