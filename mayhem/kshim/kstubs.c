// SPDX-License-Identifier: ISC
/*
 * Out-of-line part of the mt76 userspace kernel shim: sk_buff allocation, and stubs for the
 * kernel/driver functions the compiled driver files reference but the fuzzed RX paths never
 * call. A stub that is reached aborts with its name, so a shim gap shows up as a distinct crash
 * instead of silently returning a made-up value.
 */
#include "kshim.h"

unsigned long jiffies = 1000;

struct sk_buff *kshim_alloc_skb(unsigned int size, unsigned int headroom)
{
	struct sk_buff *skb = calloc(1, sizeof(*skb));
	if (!skb)
		return NULL;
	/* malloc(0) may return NULL; keep a valid (zero-length to ASan: size 0) allocation */
	skb->head = malloc(headroom + size ? headroom + size : 1);
	if (!skb->head) {
		free(skb);
		return NULL;
	}
	skb->data = skb->tail = skb->head + headroom;
	skb->end = skb->head + headroom + size;
	skb->truesize = size;
	return skb;
}

void kshim_free_skb(struct sk_buff *skb)
{
	if (!skb)
		return;
	free(skb->head);
	free(skb);
}

#define KSHIM_UNREACHED(name) \
	do { fprintf(stderr, "kshim: unimplemented %s reached\n", name); abort(); } while (0)

struct page *kshim_virt_to_head_page(const void *p) { (void)p; KSHIM_UNREACHED(__func__); }
struct page *kshim_page_pool_alloc_frag(struct page_pool *pp, unsigned int *o, unsigned int s, gfp_t g)
{ (void)pp; (void)o; (void)s; (void)g; KSHIM_UNREACHED(__func__); }
void kshim_page_pool_put_full_page(struct page_pool *pp, struct page *page, bool d)
{ (void)pp; (void)page; (void)d; KSHIM_UNREACHED(__func__); }
int kshim_usb_bulk_msg(struct usb_device *u, unsigned int p, void *d, int l, int *a, int t)
{ (void)u; (void)p; (void)d; (void)l; (void)a; (void)t; KSHIM_UNREACHED(__func__); }
struct task_struct *kshim_kthread_run(int (*fn)(void *), void *data, const char *fmt, ...)
{ (void)fn; (void)data; (void)fmt; KSHIM_UNREACHED(__func__); }
int kshim_idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp)
{ (void)idr; (void)ptr; (void)start; (void)end; (void)gfp; KSHIM_UNREACHED(__func__); }
/*
 * The fuzzed RX paths never queue a frame for TX, so no token/pktid is ever allocated
 * (idr_alloc above aborts) and every IDR is empty: lookups and removals find nothing, exactly as
 * on a device that has nothing in flight. A TX-free event naming any token then takes the
 * driver's own "!txwi" path (mt7615_mac_tx_free_token) instead of a fake shim crash.
 */
void *kshim_idr_remove(struct idr *idr, unsigned long id) { (void)idr; (void)id; return NULL; }
void *kshim_idr_find(const struct idr *idr, unsigned long id) { (void)idr; (void)id; return NULL; }
/*
 * A firmware-loader target defines kshim_firmware (the file the fuzzer supplies); every other
 * target never loads firmware, and reaching request_firmware there aborts as before.
 */
extern const struct firmware *kshim_firmware __attribute__((weak));
int kshim_request_firmware(const struct firmware **fw, const char *name, struct device *dev)
{
	(void)name; (void)dev;
	if (&kshim_firmware && kshim_firmware) {
		*fw = kshim_firmware;
		return 0;
	}
	*fw = NULL;
	KSHIM_UNREACHED(__func__);
}
struct ieee80211_hw *kshim_ieee80211_alloc_hw(size_t priv, const struct ieee80211_ops *ops)
{ (void)priv; (void)ops; KSHIM_UNREACHED(__func__); }
