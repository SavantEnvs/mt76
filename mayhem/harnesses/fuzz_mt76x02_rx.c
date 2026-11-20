// SPDX-License-Identifier: ISC
/*
 * Fuzz the mt76x02 (MT76x0/MT76x2) RX descriptor + 802.11 frame path, mt76x02_mac_process_rx()
 * in the unmodified mt76x02_mac.c, compiled against the userspace kernel shim in mayhem/kshim/.
 *
 * Input layout mirrors what mt76x02_queue_rx_skb() hands the function: the DMA buffer starts with
 * the hardware RX descriptor (struct mt76x02_rxwi), which the caller strips with skb_pull(); the
 * rest is the received frame (optional L2 pad, 802.11 header, IV, payload). The skb buffer ends
 * exactly at the received bytes, so a read past the frame's extent (skb->len) is an ASan report:
 * upstream fixes that class itself (27a48eed07 "mt76x02: validate RX padding before use",
 * 1c9854c436 "mt7615: validate MCU response lengths"), although in the kernel such a read usually
 * lands in the rest of the MT_RX_BUF_SIZE DMA buffer rather than faulting.
 *
 * Device state (2x2 chainmask, 5 GHz channel, one associated station at WCID 1 whose vif has a
 * group WCID) is fixed and set up once; the only field the function mutates, ampdu_ref, and the
 * RX status in skb->cb are reset for every input.
 */
#include "mt76x02.h"

/* mayhem/kshim/selftest_report.c defines this for the known-answer build used by mayhem/test.sh */
void kshim_selftest_report(const char *what, struct sk_buff *skb, int ret) __attribute__((weak));

static struct mt76x02_dev *dev;
static struct ieee80211_channel chan = { .band = NL80211_BAND_5GHZ, .center_freq = 5180, .hw_value = 36 };

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	struct mt76x02_sta *sta;
	struct mt76x02_vif *mvif;

	(void)argc; (void)argv;
	dev = calloc(1, sizeof(*dev));
	mvif = calloc(1, sizeof(*mvif));
	sta = calloc(1, sizeof(*sta));
	sta->vif = mvif;
	sta->wcid.idx = 1;
	dev->mt76.wcid[1] = &sta->wcid;
	dev->mphy.chainmask = 0x202;
	dev->mphy.chandef.chan = &chan;
	dev->cal.rx.rssi_offset[0] = 2;
	dev->cal.rx.rssi_offset[1] = -3;
	dev->cal.rx.lna_gain = 10;
	set_bit(MT76_STATE_RUNNING, &dev->mphy.state);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mt76x02_rxwi *rxwi;
	struct sk_buff *skb;
	int ret;

	/*
	 * mt76x02_queue_rx_skb() always strips a full RXWI from the DMA buffer before this call, and
	 * one DMA buffer holds at most MT_RX_BUF_SIZE bytes.
	 */
	if (size < sizeof(*rxwi) || size > MT_RX_BUF_SIZE)
		return -1;

	skb = kshim_alloc_skb(size, 0);
	skb_put_data(skb, data, size);
	rxwi = (struct mt76x02_rxwi *)skb->data;
	skb_pull(skb, sizeof(*rxwi));

	dev->ampdu_ref = 0;
	ret = mt76x02_mac_process_rx(dev, skb, rxwi);
	if (kshim_selftest_report)
		kshim_selftest_report("mt76x02_mac_process_rx", skb, ret);

	kshim_free_skb(skb);
	return 0;
}
