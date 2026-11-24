// SPDX-License-Identifier: ISC
/*
 * Abort stubs for the mt76 core / mt76x02 functions that the compiled mt76x02_mac.c,
 * mt76x02_txrx.c and mt76x02_util.c reference but that live in files not built into the
 * mt76x02-rx target (tx.c, mac80211.c, agg-rx.c, mcu.c, util.c, mt76x02_dfs.c, ...). None is on
 * the fuzzed RX path; reaching one aborts with its name.
 */
#include "mt76x02.h"

#define UNREACHED() do { fprintf(stderr, "kshim: %s is not part of this target\n", __func__); abort(); } while (0)

void mt76_mcu_rx_event(struct mt76_dev *dev, struct sk_buff *skb) { UNREACHED(); }
bool ____mt76_poll_msec(struct mt76_dev *dev, u32 offset, u32 mask, u32 val, int timeout, int kick) { UNREACHED(); }
void mt76_rx(struct mt76_dev *dev, enum mt76_rxq_id q, struct sk_buff *skb) { UNREACHED(); }
int mt76_rx_aggr_start(struct mt76_dev *dev, struct mt76_wcid *wcid, u8 tid, u16 ssn, u16 size) { UNREACHED(); }
void mt76_rx_aggr_stop(struct mt76_dev *dev, struct mt76_wcid *wcid, u8 tid) { UNREACHED(); }
void mt76_stop_tx_queues(struct mt76_phy *phy, struct ieee80211_sta *sta, bool send_bar) { UNREACHED(); }
void mt76_tx(struct mt76_phy *dev, struct ieee80211_sta *sta, struct mt76_wcid *wcid, struct sk_buff *skb) { UNREACHED(); }
void mt76_tx_check_agg_ssn(struct ieee80211_sta *sta, struct sk_buff *skb) { UNREACHED(); }
void __mt76_tx_complete_skb(struct mt76_dev *dev, u16 wcid, struct sk_buff *skb, struct list_head *free_list) { UNREACHED(); }
void mt76_tx_status_check(struct mt76_dev *dev, bool flush) { UNREACHED(); }
void mt76_tx_status_lock(struct mt76_dev *dev, struct sk_buff_head *list) { UNREACHED(); }
void mt76_tx_status_unlock(struct mt76_dev *dev, struct sk_buff_head *list) { UNREACHED(); }
int mt76_tx_status_skb_add(struct mt76_dev *dev, struct mt76_wcid *wcid, struct sk_buff *skb) { UNREACHED(); }
void mt76_tx_status_skb_done(struct mt76_dev *dev, struct sk_buff *skb, struct sk_buff_head *list) { UNREACHED(); }
struct sk_buff *mt76_tx_status_skb_get(struct mt76_dev *dev, struct mt76_wcid *wcid, int pktid, struct sk_buff_head *list) { UNREACHED(); }
void mt76_update_survey(struct mt76_phy *phy) { UNREACHED(); }
void mt76_wcid_cleanup(struct mt76_dev *dev, struct mt76_wcid *wcid) { UNREACHED(); }
void mt76_wcid_init(struct mt76_wcid *wcid, u8 band_idx) { UNREACHED(); }
void mt76_wcid_key_setup(struct mt76_dev *dev, struct mt76_wcid *wcid, struct ieee80211_key_conf *key) { UNREACHED(); }
void mt76x02_dfs_init_detector(struct mt76x02_dev *dev) { UNREACHED(); }
void mt76x02_mac_set_beacon_enable(struct mt76x02_dev *dev, struct ieee80211_vif *vif, bool enable) { UNREACHED(); }
void mt76x02_regd_notifier(struct wiphy *wiphy, struct regulatory_request *request) { UNREACHED(); }
void mt76x02_wdt_work(struct work_struct *work) { UNREACHED(); }
int __mt76_wcid_alloc(u32 *mask, int min, int size) { UNREACHED(); }
