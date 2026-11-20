// SPDX-License-Identifier: ISC
/*
 * Fuzz the MT7996 (Wi-Fi 7) MCU receive path, unmodified mt7996/mcu.c against mayhem/kshim/:
 *  - mt7996_mcu_rx_event(): every frame the firmware pushes on the MCU RX ring (mt7996/mac.c
 *    mt7996_queue_rx_skb, PKT_TYPE_RX_EVENT) - unsolicited UNI events (IE countdown, radar,
 *    all-STA info, WED RRO, PS sync, firmware log), legacy extended events (thermal, CSA,
 *    firmware log) and command responses, which go to mt76_mcu_rx_event()'s response queue.
 * Input: the event buffer as it comes off the ring (struct mt7996_mcu_rxd first), ending exactly
 * at the input.
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

	if (size > MT_RX_BUF_SIZE)	/* the RX ring's buffer size (mt7996/dma.c) bounds a frame */
		return -1;
	skb = kshim_alloc_skb(size, 0);
	skb_put_data(skb, data, size);
	/* consumes the skb: freed by the event handlers or queued on mcu.res_q */
	mt7996_mcu_rx_event(dev, skb);
	shim_mt7996_reset(dev);
	return 0;
}
