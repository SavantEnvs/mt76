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

/*
 * mt7996/dma.c allocates the MCU RX rings with MT7996_RX_MCU_BUF_SIZE buffers: 2048 bytes of data
 * room plus the kernel's skb_shared_info tail (mt7996.h). SKB_WITH_OVERHEAD() in the shim takes off
 * SKB_DATA_ALIGN(320) for that tail, so this is the same buffer with the same 2048-byte room.
 */
#define MCU_RX_BUF_SIZE (2048 + SKB_DATA_ALIGN(320))

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
	 * mt76_dma_rx_process() drops a frame longer than SKB_WITH_OVERHEAD(buf_size) (dma.c: data_len <
	 * len + q->buf_offset, buf_offset 0 on the MCU rings), so no longer event reaches the handler.
	 */
	if (size > SKB_WITH_OVERHEAD(MCU_RX_BUF_SIZE))
		return -1;
	/* the event sits in a whole MCU RX ring buffer, as napi_build_skb() leaves it (kshim_build_rx_skb) */
	skb = kshim_build_rx_skb(data, size, MCU_RX_BUF_SIZE, SKB_WITH_OVERHEAD(MCU_RX_BUF_SIZE));
	/* consumes the skb: freed by the event handlers or queued on mcu.res_q */
	mt7996_mcu_rx_event(dev, skb);
	shim_mt7996_reset(dev);
	return 0;
}
