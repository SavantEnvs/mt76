// SPDX-License-Identifier: ISC
/*
 * Shared device setup for the mt7615 targets: a zeroed struct mt7615_dev wired up the way
 * mt7615_mmio_probe()/mt7615_register_device() leave it for the paths fuzzed here (MMIO bus whose
 * registers read as 0, primary phy on a 5 GHz channel, running state, one associated station at
 * WCID 1 with a vif). Built once; the targets reset what an input can change.
 */
#include "mt7615/mt7615.h"
#include "mt7615/mcu.h"

/* mayhem/kshim/selftest_report.c defines this for the known-answer build used by mayhem/test.sh */
void kshim_selftest_report(const char *what, struct sk_buff *skb, int ret) __attribute__((weak));

static u32 shim_rr(struct mt76_dev *d, u32 o) { (void)d; (void)o; return 0; }
static void shim_wr(struct mt76_dev *d, u32 o, u32 v) { (void)d; (void)o; (void)v; }
static u32 shim_rmw(struct mt76_dev *d, u32 o, u32 m, u32 v) { (void)d; (void)o; (void)m; return v; }
/* the shim has no DMA rings: TX cleanup (called when a TX-free event arrives) has nothing to reap */
static void shim_tx_cleanup(struct mt76_dev *d, struct mt76_queue *q, bool flush) { (void)d; (void)q; (void)flush; }
static const struct mt76_queue_ops shim_queue_ops = { .tx_cleanup = shim_tx_cleanup };
static const struct mt76_bus_ops shim_bus = { .rr = shim_rr, .wr = shim_wr, .rmw = shim_rmw, .type = MT76_BUS_MMIO };
static struct ieee80211_channel shim_chan = { .band = NL80211_BAND_5GHZ, .center_freq = 5180, .hw_value = 36 };
static struct wiphy shim_wiphy = { .name = "phy0" };
static struct ieee80211_hw shim_hw = { .wiphy = &shim_wiphy };
static struct device shim_device;

static struct mt7615_dev *shim_mt7615_dev(u32 rev)
{
	struct mt7615_dev *dev = calloc(1, sizeof(*dev));
	struct mt7615_vif *mvif = calloc(1, sizeof(*mvif));
	struct mt7615_sta *msta = calloc(1, sizeof(*msta));

	shim_hw.priv = &dev->phy;
	dev->mt76.dev = &shim_device;
	dev->mt76.bus = &shim_bus;
	dev->mt76.queue_ops = &shim_queue_ops;
	dev->mt76.rev = rev;
	dev->mt76.hw = &shim_hw;
	dev->mt76.phy.hw = &shim_hw;
	dev->mt76.phy.dev = &dev->mt76;
	dev->mt76.phy.priv = &dev->phy;
	dev->mt76.phy.chandef.chan = &shim_chan;
	dev->mt76.phy.chainmask = 0xf;
	dev->mt76.phy.antenna_mask = 0xf;
	dev->mt76.phys[MT_BAND0] = &dev->mt76.phy;
	dev->mt76.phy.sband_5g.sband.band = NL80211_BAND_5GHZ;
	dev->mt76.phy.sband_5g.sband.channels = &shim_chan;
	dev->mt76.phy.sband_5g.sband.n_channels = 1;
	dev->mt76.phy.sband_5g.chan = calloc(1, sizeof(*dev->mt76.phy.sband_5g.chan));
	dev->mt76.phy.cap.has_5ghz = true;
	dev->phy.mt76 = &dev->mt76.phy;
	dev->phy.dev = dev;
	dev->phy.chfreq = 36;
	set_bit(MT76_STATE_RUNNING, &dev->mt76.phy.state);
	INIT_LIST_HEAD(&dev->mt76.wcid_list);
	INIT_LIST_HEAD(&dev->mt76.sta_poll_list);
	skb_queue_head_init(&dev->mt76.mcu.res_q);
	/* as mt7615_init_device() (mt7615/init.c:640-641) */
	skb_queue_head_init(&dev->phy.scan_event_list);
	skb_queue_head_init(&dev->coredump.msg_list);
	for (int i = 0; i < __MT_RXQ_MAX; i++)
		skb_queue_head_init(&dev->mt76.rx_skb[i]);

	msta->vif = mvif;
	msta->wcid.idx = 1;
	msta->wcid.sta = 1;
	INIT_LIST_HEAD(&msta->wcid.poll_list);
	INIT_LIST_HEAD(&msta->wcid.list);
	mvif->sta.wcid.idx = 2;
	INIT_LIST_HEAD(&mvif->sta.wcid.poll_list);
	INIT_LIST_HEAD(&mvif->sta.wcid.list);
	dev->mt76.wcid[1] = &msta->wcid;
	return dev;
}

/*
 * Undo everything an input can change on the device. What the RX dispatcher writes:
 *  - queues: rx_skb[] (mt76_rx), mcu.res_q (MCU responses), phy.scan_event_list (scan-done
 *    events; drained by scan_work, which never runs here), coredump.msg_list (kept for parity:
 *    the coredump stub frees the fragment instead), sta_poll_list (TX status / TX free);
 *  - phy: ampdu_ref / rx_ampdu_ts (A-MPDU grouping in mt7615_mac_fill_rx), roc_grant (ROC event);
 *  - station: airtime_ac (mt7615_mac_sta_poll; registers read 0, cleared anyway).
 * The radar event changes nothing (no DFS region, mt76_phy_dfs_state() is DISABLED), and the CSA,
 * beacon-loss and BSS-absence events only call mac80211 hooks the shim makes no-ops.
 */
static void shim_mt7615_reset(struct mt7615_dev *dev)
{
	struct mt76_wcid *w, *n;

	if (kshim_selftest_report) {
		struct sk_buff *skb;

		skb_queue_walk(&dev->mt76.rx_skb[MT_RXQ_MAIN], skb)
			kshim_selftest_report("rx_skb[MAIN]", skb, 0);
		skb_queue_walk(&dev->mt76.mcu.res_q, skb)
			kshim_selftest_report("mcu.res_q", skb, 0);
	}
	__skb_queue_purge(&dev->mt76.mcu.res_q);
	__skb_queue_purge(&dev->phy.scan_event_list);
	__skb_queue_purge(&dev->coredump.msg_list);
	dev->phy.ampdu_ref = 0;
	dev->phy.rx_ampdu_ts = 0;
	dev->phy.roc_grant = false;
	if (dev->mt76.wcid[1])
		memset(container_of(dev->mt76.wcid[1], struct mt7615_sta, wcid)->airtime_ac, 0,
		       sizeof(((struct mt7615_sta *)0)->airtime_ac));
	for (int i = 0; i < __MT_RXQ_MAX; i++)
		__skb_queue_purge(&dev->mt76.rx_skb[i]);
	list_for_each_entry_safe(w, n, &dev->mt76.sta_poll_list, poll_list)
		list_del_init(&w->poll_list);
}
