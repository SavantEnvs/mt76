// SPDX-License-Identifier: ISC
/*
 * Fuzz mt7996_queue_rx_skb() (unmodified mt7996/mac.c, against mayhem/kshim/): the MT7996
 * (Wi-Fi 7) RX dispatcher for every buffer the RX DMA rings hand over (mcu_ops->rx_skb): data
 * and management frames (mt7996_mac_fill_rx: RX descriptor groups, rate/HE/EHT RXV, header
 * translation, A-MSDU, then the mt76 core RX path and reorder buffer), TX-free notifications,
 * TX status, and MCU events (mt7996_mcu_rx_event). Input: one RX buffer, RX descriptor first.
 */
#include "fuzz_mt7996_common.h"

static struct mt7996_dev *dev;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	dev = shim_mt7996_dev();
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
	 * fixed part of the hardware RX descriptor, RXD DW0..DW7 (mt76_connac3_mac.h MT_RXD0_*..),
	 * which the MAC always writes; mt7996_mac_fill_rx() reads DW0..DW4 unconditionally.
	 */
	if (size < 8 * sizeof(__le32) || size > MT_RX_BUF_SIZE)
		return -1;
	skb = kshim_alloc_skb(size, 0);
	skb_put_data(skb, data, size);
	mt7996_queue_rx_skb(&dev->mt76, MT_RXQ_MAIN, skb, &info);
	shim_mt7996_reset(dev);
	return 0;
}
