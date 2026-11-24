// SPDX-License-Identifier: ISC
/*
 * Fuzz the mt76x02 (MT76x0/MT76x2) RX descriptor + 802.11 frame path, mt76x02_mac_process_rx()
 * in the unmodified mt76x02_mac.c, compiled against the userspace kernel shim in mayhem/kshim/.
 *
 * Input layout mirrors what mt76x02_queue_rx_skb() hands the function: the DMA buffer starts with
 * the hardware RX descriptor (struct mt76x02_rxwi), which the caller strips with skb_pull(); the
 * rest is the received frame (optional L2 pad, 802.11 header, IV, payload). The skb is built as
 * mt76_dma_rx_process() builds it for this ring (kshim_build_rx_skb_off): one MT_RX_BUF_SIZE buffer,
 * skb_reserve(q->buf_offset) with buf_offset = MT_RX_HEADROOM - sizeof(rxwi) (mt76x02_mmio.c), so a
 * driver read past skb->len that stays inside the real DMA buffer reads zeroes (stale ring data in
 * the kernel) and only a read past that buffer is an ASan report.
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

	const unsigned int buf_offset = MT_RX_HEADROOM - sizeof(*rxwi);
	const unsigned int room = SKB_WITH_OVERHEAD(MT_RX_BUF_SIZE);

	/*
	 * mt76x02_queue_rx_skb() always strips a full RXWI from the DMA buffer before this call, and
	 * mt76_dma_rx_process() drops a frame with len + q->buf_offset > SKB_WITH_OVERHEAD(buf_size).
	 */
	if (size < sizeof(*rxwi) || size + buf_offset > room)
		return -1;

	skb = kshim_build_rx_skb_off(data, size, MT_RX_BUF_SIZE, room, buf_offset);
	rxwi = (struct mt76x02_rxwi *)skb->data;
	skb_pull(skb, sizeof(*rxwi));

	dev->ampdu_ref = 0;
	ret = mt76x02_mac_process_rx(dev, skb, rxwi);
	if (kshim_selftest_report)
		kshim_selftest_report("mt76x02_mac_process_rx", skb, ret);

	kshim_free_skb(skb);
	return 0;
}
