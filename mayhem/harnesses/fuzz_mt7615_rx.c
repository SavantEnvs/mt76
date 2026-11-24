// SPDX-License-Identifier: ISC
/*
 * Fuzz the mt7615 RX dispatcher mt7615_queue_rx_skb() (unmodified mt7615/mac.c + mt7615/mcu.c,
 * compiled against mayhem/kshim/): every buffer the RX DMA ring delivers goes through it, and it
 * parses, by the RXD packet type, TX status reports (mt7615_mac_add_txs), TX-free notifications
 * (mt7615_mac_tx_free), firmware MCU events (mt7615_mcu_rx_event) and received 802.11 frames
 * with their RX descriptors (mt7615_mac_fill_rx). The input is the whole DMA buffer; the skb
 * ends exactly at the input so a read past the delivered bytes is an ASan report.
 */
#include "fuzz_mt7615_common.h"

static struct mt7615_dev *dev;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	dev = shim_mt7615_dev(0x76150000);
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
	 * fixed part of the hardware RX descriptor, RXD DW0..DW3 (mt7615/mac.h MT_RXD0_*..MT_RXD3_*),
	 * which the MAC always writes and the driver reads unconditionally.
	 */
	if (size < 4 * sizeof(__le32) || size > SKB_WITH_OVERHEAD(MT_RX_BUF_SIZE))
		return -1;
	/* the frame sits in a whole RX ring buffer, as napi_build_skb() leaves it (kshim_build_rx_skb) */
	skb = kshim_build_rx_skb(data, size, MT_RX_BUF_SIZE, SKB_WITH_OVERHEAD(MT_RX_BUF_SIZE));
	mt7615_queue_rx_skb(&dev->mt76, MT_RXQ_MAIN, skb, &info);
	shim_mt7615_reset(dev);
	return 0;
}
