// SPDX-License-Identifier: ISC
/*
 * Fuzz the MT7921/MT7922 (Wi-Fi 6E) MCU receive path, unmodified mt7921/mcu.c against
 * mayhem/kshim/: mt7921_mcu_rx_event() for every frame the firmware pushes on the MCU RX ring
 * (mt7921/mac.c mt7921_queue_rx_skb, PKT_TYPE_RX_EVENT) - unsolicited events (beacon loss, scan
 * done, firmware debug message, coredump, low-power info, TX done, RSSI monitor, ROC grant) and
 * command responses, which go to mt76_mcu_rx_event()'s response queue.
 * Input: the event buffer as it comes off the ring, struct mt76_connac2_mcu_rxd first.
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
	 * mt76_dma_rx_process() drops a frame longer than SKB_WITH_OVERHEAD(buf_size) (dma.c: data_len <
	 * len + q->buf_offset, buf_offset 0 on the MCU rings), so no longer event reaches the handler.
	 */
	if (size > SKB_WITH_OVERHEAD(MT_RX_BUF_SIZE))
		return -1;
	/* the event sits in a whole MCU RX ring buffer, as napi_build_skb() leaves it (kshim_build_rx_skb) */
	skb = kshim_build_rx_skb(data, size, MT_RX_BUF_SIZE, SKB_WITH_OVERHEAD(MT_RX_BUF_SIZE));
	/* consumes the skb: freed by the event handlers or queued on mcu.res_q */
	mt7921_mcu_rx_event(dev, skb);
	shim_mt7921_reset(dev);
	return 0;
}
