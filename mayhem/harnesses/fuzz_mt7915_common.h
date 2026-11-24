// SPDX-License-Identifier: ISC
/*
 * Shared device setup for the mt7915 targets: a zeroed struct mt7915_dev (chip 0x7915, MT7915)
 * wired up the way mt7915_mmio_probe()/mt7915_register_device() leave it for the paths fuzzed
 * here (MMIO bus whose registers read as 0, primary phy on band 0 on a 5 GHz channel, running
 * state, no WED). Built once; the targets reset what an input can change.
 */
#include "mt7915/mt7915.h"
#include "mt7915/mcu.h"
#include "mt7915/mac.h"

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

static struct mt7915_dev *shim_mt7915_dev(void)
{
	struct mt7915_dev *d = calloc(1, sizeof(*d));

	shim_hw.priv = &d->phy;
	d->mt76.dev = &shim_device;
	d->mt76.bus = &shim_bus;
	d->mt76.queue_ops = &shim_queue_ops;
	d->mt76.rev = 0x79150000;
	d->mt76.hw = &shim_hw;
	d->mt76.phy.hw = &shim_hw;
	d->mt76.phy.dev = &d->mt76;
	d->mt76.phy.priv = &d->phy;
	d->mt76.phy.chandef.chan = &shim_chan;
	d->mt76.phy.chainmask = 0xf;
	d->mt76.phy.antenna_mask = 0xf;
	d->mt76.phys[MT_BAND0] = &d->mt76.phy;
	d->mt76.phy.sband_5g.sband.band = NL80211_BAND_5GHZ;
	d->mt76.phy.sband_5g.sband.channels = &shim_chan;
	d->mt76.phy.sband_5g.sband.n_channels = 1;
	d->mt76.phy.sband_5g.chan = calloc(1, sizeof(*d->mt76.phy.sband_5g.chan));
	d->mt76.phy.cap.has_5ghz = true;
	d->phy.mt76 = &d->mt76.phy;
	d->phy.dev = d;
	set_bit(MT76_STATE_RUNNING, &d->mt76.phy.state);
	INIT_LIST_HEAD(&d->mt76.wcid_list);
	INIT_LIST_HEAD(&d->mt76.sta_poll_list);
	skb_queue_head_init(&d->mt76.mcu.res_q);
	for (int i = 0; i < __MT_RXQ_MAX; i++)
		skb_queue_head_init(&d->mt76.rx_skb[i]);
	return d;
}

/* Undo what an input can change: the MCU response queue (mt76_mcu_rx_event), the RX queues
 * (mt76_rx), the phy's A-MPDU state (mt7915_mac_fill_rx), the thermal throttle state (thermal
 * notify) and the station poll list (TX free / TX status). */
static void shim_mt7915_reset(struct mt7915_dev *d)
{
	struct mt76_wcid *w, *n;

	if (kshim_selftest_report) {
		struct sk_buff *skb;

		skb_queue_walk(&d->mt76.rx_skb[MT_RXQ_MAIN], skb)
			kshim_selftest_report("rx_skb[MAIN]", skb, 0);
		skb_queue_walk(&d->mt76.mcu.res_q, skb)
			kshim_selftest_report("mcu.res_q", skb, 0);
	}
	__skb_queue_purge(&d->mt76.mcu.res_q);
	for (int i = 0; i < __MT_RXQ_MAX; i++)
		__skb_queue_purge(&d->mt76.rx_skb[i]);
	d->phy.throttle_state = 0;
	d->phy.cdev_state = 0;
	d->phy.ampdu_ref = 0;
	d->phy.rx_ampdu_ts = 0;
	list_for_each_entry_safe(w, n, &d->mt76.sta_poll_list, poll_list)
		list_del_init(&w->poll_list);
}
