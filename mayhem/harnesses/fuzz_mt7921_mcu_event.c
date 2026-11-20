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

	if (size > MT_RX_BUF_SIZE)	/* the RX ring's buffer size bounds a frame */
		return -1;
	skb = kshim_alloc_skb(size, 0);
	skb_put_data(skb, data, size);
	/* consumes the skb: freed by the event handlers or queued on mcu.res_q */
	mt7921_mcu_rx_event(dev, skb);
	shim_mt7921_reset(dev);
	return 0;
}
