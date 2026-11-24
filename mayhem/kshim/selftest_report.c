// SPDX-License-Identifier: ISC
/*
 * Known-answer hook for mayhem/test.sh: linked (with normal flags, no sanitizers) into the
 * *_selftest builds of the shim targets, it prints what the driver produced for each input -
 * return code, the frame left in the skb and the RX status the driver filled in skb->cb - so
 * test.sh can diff it against golden output in mayhem/expected/.
 */
#include "mt76.h"

void kshim_selftest_report(const char *what, struct sk_buff *skb, int ret)
{
	struct mt76_rx_status *st = (struct mt76_rx_status *)skb->cb;
	unsigned int i;

	printf("%s ret=%d len=%u", what, ret, skb->len);
	printf(" flag=%#x enc=%u bw=%u rate=%u nss=%u enc_flags=%#x chains=%#x sig=%d,%d",
	       st->flag, st->encoding, st->bw, st->rate_idx, st->nss, st->enc_flags, st->chains,
	       st->chain_signal[0], st->chain_signal[1]);
	printf(" freq=%u band=%u aggr=%u qos=%#x seq=%u iv=", st->freq, st->band, st->aggr, st->qos_ctl, st->seqno);
	for (i = 0; i < sizeof(st->iv); i++)
		printf("%02x", st->iv[i]);
	printf(" data=");
	for (i = 0; i < skb->len && i < 32; i++)
		printf("%02x", skb->data[i]);
	printf("\n");
	fflush(stdout);
}
