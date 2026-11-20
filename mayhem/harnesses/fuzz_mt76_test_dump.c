// SPDX-License-Identifier: ISC
/*
 * Fuzz the mt76-test tool's testmode dump path (tools/main.c mt76_dump_cb ->
 * tools/fields.c print_nested / print_array / per-type printers, through
 * libnl-tiny's nla_parse / nlmsg_find_attr).
 *
 * In the real tool these attributes arrive as the kernel's reply to an
 * NL80211_CMD_TESTMODE dump: the input is the attribute stream that follows the
 * genetlink header of that reply. The harness wraps it into an nl_msg exactly as
 * libnl-tiny receives one (nlmsghdr + genlmsghdr + attributes) and hands it to
 * the tool's own callback, mt76_dump_cb().
 *
 * tools/main.c is included so the static callback is reachable; its main() is
 * renamed. No state survives an input: the message is built and freed per call,
 * and `unl` only carries the constant genetlink header length.
 */
#define main mt76_test_main
#include "../../tools/main.c"
#undef main

#include <netlink/genl/genl.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct nl_msg *msg;

	/* nlmsg_len is 32-bit and libnl-tiny caps allocations; keep inputs sane. */
	if (size > 65536)
		return -1;

	unl.hdrlen = NLMSG_ALIGN(sizeof(struct genlmsghdr));

	/*
	 * Size the message exactly (libnl-tiny callocs this length): headers plus the
	 * attribute stream padded by nlmsg_append to NLMSG_ALIGNTO. No slack, so a
	 * read past the reply lands in ASan's redzone instead of zeroed padding.
	 */
	msg = nlmsg_alloc_size(NLMSG_HDRLEN + GENL_HDRLEN + NLMSG_ALIGN(size));
	if (!msg)
		return 0;

	if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, 0, 0, 0,
			 NL80211_CMD_TESTMODE, 0) ||
	    nlmsg_append(msg, (void *)data, size, NLMSG_ALIGNTO) < 0) {
		nlmsg_free(msg);
		return 0;
	}

	mt76_dump_cb(msg, NULL);
	fflush(stdout);

	nlmsg_free(msg);
	return 0;
}
