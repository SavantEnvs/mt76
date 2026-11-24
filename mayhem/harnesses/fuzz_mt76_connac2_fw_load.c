// SPDX-License-Identifier: ISC
/*
 * Fuzz the connac2 firmware loader, unmodified mt76_connac_mcu.c against mayhem/kshim/: the two
 * calls mt792x_load_firmware() (mt792x_core.c) makes for MT7921/MT7922 at probe and on every
 * reset - mt76_connac2_load_patch() (ROM patch file: big-endian patch header, section table,
 * mt76_connac2_patch_check) and mt76_connac2_load_ram() (WM RAM file: region table and trailer
 * at the end of the file, mt76_connac2_fw_check), which split the file into download regions
 * and stream them to the MCU in FW_SCATTER chunks.
 * Input: byte 0 bit 0 selects the loader (1 = patch, 0 = RAM); the rest is the firmware file
 * that request_firmware() returns.
 */
#include "fuzz_mt7921_common.h"

const struct firmware *kshim_firmware;
static struct mt792x_dev *dev;
static volatile u8 fw_sink;
/* what the MCU received for one input: commands, and bytes in FW_SCATTER chunks (known-answer build) */
static u32 fw_cmds, fw_scatter_bytes;

/*
 * The MCU side of the download: it receives every command (patch semaphore, download request,
 * FW_SCATTER chunks, patch/firmware start) and answers like a device with no patch loaded yet.
 * Every byte the driver sends is read here, as the DMA engine would, so a chunk that runs past
 * the end of the firmware file is caught.
 */
static int fw_mcu_send_msg(struct mt76_dev *mdev, int cmd, const void *data, int len, bool wait_resp)
{
	const u8 *p = data;
	u8 acc = 0;

	(void)mdev; (void)wait_resp;
	for (int i = 0; i < len; i++)
		acc ^= p[i];
	fw_sink = acc;
	fw_cmds++;
	if (cmd == MCU_CMD(FW_SCATTER))
		fw_scatter_bytes += len;
	if (cmd == MCU_CMD(PATCH_SEM_CONTROL)) {
		const __le32 *op = data;

		return le32_to_cpu(*op) == PATCH_SEM_GET ? PATCH_NOT_DL_SEM_SUCCESS : PATCH_REL_SEM_SUCCESS;
	}
	return 0;
}
static const struct mt76_mcu_ops fw_mcu_ops = { .mcu_send_msg = fw_mcu_send_msg };

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	dev = shim_mt7921_dev();
	dev->mt76.mcu_ops = &fw_mcu_ops;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct firmware fw;
	u8 *copy;
	int ret;

	if (size < 1)
		return -1;
	/* request_firmware() hands over an exactly-sized buffer holding the file */
	copy = malloc(size - 1 ? size - 1 : 1);
	memcpy(copy, data + 1, size - 1);
	fw.data = copy;
	fw.size = size - 1;
	kshim_firmware = &fw;
	if (data[0] & 1)
		ret = mt76_connac2_load_patch(&dev->mt76, "mt7961_patch_mcu_1_2_hdr.bin");
	else
		ret = mt76_connac2_load_ram(&dev->mt76, "WIFI_RAM_CODE_MT7961_1.bin", NULL);
	if (kshim_selftest_report) {
		struct wiphy *wiphy = dev->mt76.hw->wiphy;
		struct sk_buff *skb = kshim_alloc_skb(8 + sizeof(wiphy->fw_version), 0);
		__le32 counts[2] = { cpu_to_le32(fw_cmds), cpu_to_le32(fw_scatter_bytes) };

		/* printed: MCU command count, FW_SCATTER byte count, then the version string set */
		skb_put_data(skb, counts, sizeof(counts));
		skb_put_data(skb, wiphy->fw_version, sizeof(wiphy->fw_version));
		kshim_selftest_report(data[0] & 1 ? "load_patch" : "load_ram", skb, ret);
		kfree_skb(skb);
	}
	fw_cmds = fw_scatter_bytes = 0;
	/* the only device state a load leaves behind: the firmware version string it copied to the wiphy */
	memset(dev->mt76.hw->wiphy->fw_version, 0, sizeof(dev->mt76.hw->wiphy->fw_version));
	kshim_firmware = NULL;
	free(copy);
	return 0;
}
