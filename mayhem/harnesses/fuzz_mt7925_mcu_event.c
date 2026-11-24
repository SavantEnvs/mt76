// SPDX-License-Identifier: ISC
/*
 * Fuzz the MT7925 (Wi-Fi 7) MCU receive path, unmodified mt7925/mcu.c against
 * mayhem/kshim/: mt7925_mcu_rx_event() for every frame the firmware pushes on the MCU RX ring
 * (mt7925/mac.c mt7925_queue_rx_skb, PKT_TYPE_RX_EVENT) - unsolicited events (UNI events: HIF control, firmware log,
 * ROC, MBMC, scan done, TX done, beacon loss, P2P SAP / BSS absence, RSSI monitor, coredump) and
 * command responses, which go to mt76_mcu_rx_event()'s response queue.
 * Input: the event buffer as it comes off the ring, struct mt7925_mcu_rxd first.
 */
#include "fuzz_mt7925_common.h"

static struct mt792x_dev *dev;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	dev = shim_mt7925_dev();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct sk_buff *skb;

	/*
	 * mt76_dma_rx_process() drops a frame longer than SKB_WITH_OVERHEAD(buf_size) (dma.c: data_len <
	 * len + q->buf_offset, buf_offset 0 on the MCU rings), so no longer event reaches the handler.
	 */
	if (size > SKB_WITH_OVERHEAD(MT_RX_BUF_SIZE))
		return -1;
	/* the event sits in a whole MCU RX ring buffer, as napi_build_skb() leaves it (kshim_build_rx_skb) */
	skb = kshim_build_rx_skb(data, size, MT_RX_BUF_SIZE, SKB_WITH_OVERHEAD(MT_RX_BUF_SIZE));
	/* consumes the skb: freed by the event handlers or queued on mcu.res_q */
	mt7925_mcu_rx_event(dev, skb);
	shim_mt7925_reset(dev);
	return 0;
}
