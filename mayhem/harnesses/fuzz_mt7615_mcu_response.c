// SPDX-License-Identifier: ISC
/*
 * Fuzz mt7615_mcu_parse_response() (unmodified mt7615/mcu.c, against mayhem/kshim/): the parser
 * for the firmware's reply to every MCU command the driver sends (mcu_ops->mcu_parse_response,
 * called by mt76_mcu_skb_send_and_get_msg()). Input: byte 0 picks the command whose reply is
 * parsed (index into the commands the parser special-cases, plus one generic command) and the
 * chip (bit 7: MT7663, else MT7615), byte 1 is the sequence number the driver expects; the rest
 * is the firmware's response buffer, ending exactly at the input.
 */
#include "fuzz_mt7615_common.h"

static struct mt7615_dev *dev7615, *dev7663;

static const int cmds[] = {
	MCU_CMD(PATCH_SEM_CONTROL), MCU_EXT_CMD(THERMAL_CTRL), MCU_EXT_QUERY(RF_REG_ACCESS),
	MCU_UNI_CMD(DEV_INFO_UPDATE), MCU_UNI_CMD(BSS_INFO_UPDATE), MCU_UNI_CMD(STA_REC_UPDATE),
	MCU_UNI_CMD(HIF_CTRL), MCU_UNI_CMD(OFFLOAD), MCU_UNI_CMD(SUSPEND), MCU_CE_QUERY(REG_READ),
	MCU_EXT_CMD(PM_STATE_CTRL),
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	dev7615 = shim_mt7615_dev(0x76150000);
	dev7663 = shim_mt7615_dev(0x76630000);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mt7615_dev *dev;
	struct sk_buff *skb;
	int cmd, seq, ret;

	if (size < 2 || size - 2 > MT_RX_BUF_SIZE)
		return -1;
	dev = (data[0] & 0x80) ? dev7663 : dev7615;
	cmd = cmds[(data[0] & 0x7f) % ARRAY_SIZE(cmds)];
	seq = data[1];
	skb = kshim_alloc_skb(size - 2, 0);
	skb_put_data(skb, data + 2, size - 2);
	ret = mt7615_mcu_parse_response(&dev->mt76, cmd, skb, seq);
	if (kshim_selftest_report)
		kshim_selftest_report("mt7615_mcu_parse_response", skb, ret);
	kshim_free_skb(skb);
	return 0;
}
