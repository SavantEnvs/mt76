// SPDX-License-Identifier: ISC
/*
 * Fuzz the MT7915/MT7916 (Wi-Fi 6) MCU receive path, unmodified mt7915/mcu.c against
 * mayhem/kshim/: mt7915_mcu_rx_event() for every frame the firmware pushes on the MCU RX ring
 * (mt7915/mac.c mt7915_queue_rx_skb, PKT_TYPE_RX_EVENT) - unsolicited extended events (thermal
 * protection, firmware log, assert dump, PS sync, BCC / CSA countdown, rate report, ...) and
 * command responses, which go to mt76_mcu_rx_event()'s response queue.
 * Input: the event buffer as it comes off the ring, struct mt76_connac2_mcu_rxd first.
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
	 * An MCU event buffer from the RX ring (at most MT_RX_BUF_SIZE bytes) always starts with the
	 * firmware's event header, struct mt76_connac2_mcu_rxd (mt76_connac_mcu.h), which
	 * mt7915_mcu_rx_event() reads before any length check.
	 */
	if (size < sizeof(struct mt76_connac2_mcu_rxd) || size > MT_RX_BUF_SIZE)
		return -1;
	skb = kshim_alloc_skb(size, 0);
	skb_put_data(skb, data, size);
	/* consumes the skb: freed by the event handlers or queued on mcu.res_q */
	mt7915_mcu_rx_event(dev, skb);
	shim_mt7915_reset(dev);
	return 0;
}
