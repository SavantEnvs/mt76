// SPDX-License-Identifier: ISC
/*
 * Fuzz mt7915_queue_rx_skb() (unmodified mt7915/mac.c, against mayhem/kshim/): the MT7915
 * (Wi-Fi 6) RX dispatcher for every buffer the RX DMA rings hand over (mcu_ops->rx_skb): data
 * and management frames (mt7915_mac_fill_rx: RX descriptor groups, rate/HE RXV, header
 * translation, A-MSDU, then the mt76 core RX path and reorder buffer), TX-free notifications,
 * TX status, and MCU events (mt7915_mcu_rx_event). Input: one RX buffer, RX descriptor first.
 */
#include "fuzz_mt7915_common.h"

static struct mt7915_dev *dev;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	dev = shim_mt7915_dev();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct sk_buff *skb;
	/*
	 * The RX DMA descriptor's info word, which mt76_dma_rx_process() hands to rx_skb() by pointer
	 * (dma.c: dev->drv->rx_skb(dev, q - dev->q_rx, skb, &info)); it is never NULL. Only its
	 * PPE bits are read, and only for a WED RX queue with a station, which the shim has none of.
	 */
	u32 info = 0;

	/*
	 * The RX DMA ring buffers are MT_RX_BUF_SIZE bytes and mt76_dma_rx_process() drops a frame longer
	 * than SKB_WITH_OVERHEAD(MT_RX_BUF_SIZE) (dma.c: data_len < len + q->buf_offset); each starts with the
	 * fixed part of the hardware RX descriptor, RXD DW0..DW5 (mt76_connac2_mac.h MT_RXD0_*..; mt7915_mac_fill_rx() skips 6 DWs),
	 * which the MAC always writes.
	 */
	if (size < 6 * sizeof(__le32) || size > SKB_WITH_OVERHEAD(MT_RX_BUF_SIZE))
		return -1;
	/* the frame sits in a whole RX ring buffer, as napi_build_skb() leaves it (kshim_build_rx_skb) */
	skb = kshim_build_rx_skb(data, size, MT_RX_BUF_SIZE, SKB_WITH_OVERHEAD(MT_RX_BUF_SIZE));
	mt7915_queue_rx_skb(&dev->mt76, MT_RXQ_MAIN, skb, &info);
	shim_mt7915_reset(dev);
	return 0;
}
