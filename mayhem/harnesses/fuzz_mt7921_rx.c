// SPDX-License-Identifier: ISC
/*
 * Fuzz mt7921_queue_rx_skb() (unmodified mt7921/mac.c, against mayhem/kshim/): the MT7921
 * (Wi-Fi 6) RX dispatcher for every buffer the RX DMA rings hand over (mcu_ops->rx_skb): data
 * and management frames (mt7921_mac_fill_rx: RX descriptor groups, rate/HE RXV, header
 * translation, A-MSDU, then the mt76 core RX path and reorder buffer), TX-free notifications,
 * TX status, and MCU events (mt7921_mcu_rx_event). Input: one RX buffer, RX descriptor first.
 */
#include "fuzz_mt7921_common.h"

static struct mt792x_dev *dev;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	dev = shim_mt7921_dev();
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
	 * The RX DMA ring hands over buffers of at most MT_RX_BUF_SIZE bytes, each starting with the
	 * fixed part of the hardware RX descriptor, RXD DW0..DW5 (mt76_connac2_mac.h MT_RXD0_*..; mt7921_mac_fill_rx() skips 6 DWs),
	 * which the MAC always writes.
	 */
	if (size < 6 * sizeof(__le32) || size > MT_RX_BUF_SIZE)
		return -1;
	skb = kshim_alloc_skb(size, 0);
	skb_put_data(skb, data, size);
	mt7921_queue_rx_skb(&dev->mt76, MT_RXQ_MAIN, skb, &info);
	shim_mt7921_reset(dev);
	return 0;
}
