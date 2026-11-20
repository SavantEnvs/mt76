/* SPDX-License-Identifier: ISC */
/*
 * Linear sk_buff for the mt76 userspace shim (included by kshim.h). The fuzz harness puts the
 * input bytes in a heap buffer sized exactly to [head, end), so any driver read past the frame is
 * an ASan heap-buffer-overflow. skb_push/skb_put past the buffer panic like the kernel's
 * skb_under_panic()/skb_over_panic() do (abort).
 */
#ifndef MT76_KSHIM_SKB_H
#define MT76_KSHIM_SKB_H

struct sk_buff;
struct skb_shared_info {
	u8 nr_frags;
	u8 tx_flags;
	unsigned short gso_size;
	struct sk_buff *frag_list;
};

struct sk_buff {
	union { struct { struct sk_buff *next, *prev; }; struct list_head list; };
	struct net_device *dev;
	char cb[48] __aligned(8);
	unsigned int len, data_len;
	u16 mac_len, hdr_len, mac_header;
	u16 queue_mapping;
	u16 protocol;
	u8 priority;
	u8 ip_summed;
	u32 hash;
	ktime_t tstamp;
	unsigned char *head, *data, *tail, *end;
	unsigned int truesize;
	struct skb_shared_info shinfo;
	void *destructor_arg;
};

struct sk_buff_head {
	struct sk_buff *next, *prev;
	u32 qlen;
	spinlock_t lock;
};

#define CHECKSUM_NONE 0
#define CHECKSUM_UNNECESSARY 1
#define CHECKSUM_PARTIAL 3
#define SKB_TRUESIZE(x) (x)

static inline struct skb_shared_info *skb_shinfo(const struct sk_buff *skb)
{ return (struct skb_shared_info *)&skb->shinfo; }
static inline unsigned char *skb_mac_header(const struct sk_buff *skb) { return skb->head + skb->mac_header; }
static inline bool skb_is_nonlinear(const struct sk_buff *skb) { return skb->data_len; }
static inline unsigned int skb_headlen(const struct sk_buff *skb) { return skb->len - skb->data_len; }
static inline unsigned int skb_headroom(const struct sk_buff *skb) { return skb->data - skb->head; }
static inline int skb_tailroom(const struct sk_buff *skb) { return skb_is_nonlinear(skb) ? 0 : skb->end - skb->tail; }
static inline unsigned char *skb_tail_pointer(const struct sk_buff *skb) { return skb->tail; }
static inline void skb_reset_tail_pointer(struct sk_buff *skb) { skb->tail = skb->data; }
static inline void skb_set_tail_pointer(struct sk_buff *skb, int off) { skb->tail = skb->data + off; }

static inline void *skb_put(struct sk_buff *skb, unsigned int len)
{
	void *tmp = skb->tail;
	skb->tail += len;
	skb->len += len;
	if (skb->tail > skb->end) {
		fprintf(stderr, "skb_over_panic: len %u\n", len);
		abort();
	}
	return tmp;
}
static inline void *__skb_put(struct sk_buff *skb, unsigned int len) { return skb_put(skb, len); }
static inline void *skb_put_data(struct sk_buff *skb, const void *d, unsigned int len)
{ void *t = skb_put(skb, len); memcpy(t, d, len); return t; }
static inline void *skb_put_zero(struct sk_buff *skb, unsigned int len)
{ void *t = skb_put(skb, len); memset(t, 0, len); return t; }
static inline void *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data -= len;
	skb->len += len;
	if (skb->data < skb->head) {
		fprintf(stderr, "skb_under_panic: len %u\n", len);
		abort();
	}
	return skb->data;
}
#define __skb_push skb_push
static inline void *__skb_pull(struct sk_buff *skb, unsigned int len)
{
	skb->len -= len;
	if (skb->len < skb->data_len)
		BUG();
	return skb->data += len;
}
static inline void *skb_pull(struct sk_buff *skb, unsigned int len)
{ return len > skb->len ? NULL : __skb_pull(skb, len); }
static inline void *skb_pull_data(struct sk_buff *skb, size_t len)
{ void *d = skb->data; if (skb->len < len) return NULL; skb_pull(skb, len); return d; }
static inline void __skb_trim(struct sk_buff *skb, unsigned int len)
{ skb->len = len; skb_set_tail_pointer(skb, len); }
static inline void skb_trim(struct sk_buff *skb, unsigned int len) { if (skb->len > len) __skb_trim(skb, len); }
static inline int pskb_trim(struct sk_buff *skb, unsigned int len)
{ if (len < skb->len) __skb_trim(skb, len); return 0; }
static inline bool pskb_may_pull(struct sk_buff *skb, unsigned int len) { return len <= skb->len; }
static inline void skb_reserve(struct sk_buff *skb, int len) { skb->data += len; skb->tail += len; }
static inline void skb_set_queue_mapping(struct sk_buff *skb, u16 q) { skb->queue_mapping = q; }
static inline u16 skb_get_queue_mapping(const struct sk_buff *skb) { return skb->queue_mapping; }
static inline void skb_mark_for_recycle(struct sk_buff *skb) { (void)skb; }
static inline int skb_linearize(struct sk_buff *skb) { (void)skb; return 0; }
static inline void skb_orphan(struct sk_buff *skb) { (void)skb; }
static inline void skb_set_hash(struct sk_buff *skb, u32 h, int t) { (void)t; skb->hash = h; }
static inline void skb_copy_from_linear_data(const struct sk_buff *skb, void *to, unsigned int len)
{ memcpy(to, skb->data, len); }
static inline void skb_copy_from_linear_data_offset(const struct sk_buff *skb, int off, void *to, unsigned int len)
{ memcpy(to, skb->data + off, len); }
static inline int skb_copy_bits(const struct sk_buff *skb, int off, void *to, int len)
{ if (off < 0 || len < 0 || (unsigned int)(off + len) > skb->len) return -EFAULT; memcpy(to, skb->data + off, len); return 0; }
static inline int skb_padto(struct sk_buff *skb, unsigned int len) { (void)skb; (void)len; return 0; }
static inline int skb_cow_head(struct sk_buff *skb, unsigned int h) { (void)skb; (void)h; return 0; }
static inline int skb_cow(struct sk_buff *skb, unsigned int h) { (void)skb; (void)h; return 0; }
static inline bool skb_has_frag_list(const struct sk_buff *skb) { return skb_shinfo(skb)->frag_list != NULL; }
#define skb_walk_frags(skb, iter) for (iter = skb_shinfo(skb)->frag_list; iter; iter = iter->next)

/* allocation: a linear buffer with the requested size and NET_SKB_PAD-free headroom */
struct sk_buff *kshim_alloc_skb(unsigned int size, unsigned int headroom);
void kshim_free_skb(struct sk_buff *skb);
#define alloc_skb(size, gfp) kshim_alloc_skb((size), 0)
#define dev_alloc_skb(size) kshim_alloc_skb((size), 0)
#define __dev_alloc_skb(size, gfp) kshim_alloc_skb((size), 0)
#define dev_kfree_skb(skb) kshim_free_skb(skb)
#define dev_kfree_skb_any(skb) kshim_free_skb(skb)
#define dev_kfree_skb_irq(skb) kshim_free_skb(skb)
#define kfree_skb(skb) kshim_free_skb(skb)
#define consume_skb(skb) kshim_free_skb(skb)
static inline void kfree_skb_list(struct sk_buff *s) { while (s) { struct sk_buff *n = s->next; kshim_free_skb(s); s = n; } }

static inline struct sk_buff *skb_get(struct sk_buff *skb) { fprintf(stderr, "kshim: skb_get (refcounted skb) unsupported\n"); abort(); return skb; }

static inline void skb_list_del_init(struct sk_buff *skb) { list_del_init(&skb->list); }

static inline int __skb_pad(struct sk_buff *skb, int pad, bool free_on_error)
{ (void)free_on_error; if (skb_tailroom(skb) < pad) return -ENOMEM; memset(skb->data + skb->len, 0, pad); return 0; }

/* queues */
static inline void __skb_queue_head_init(struct sk_buff_head *l) { l->prev = l->next = (struct sk_buff *)l; l->qlen = 0; }
#define skb_queue_head_init __skb_queue_head_init
static inline u32 skb_queue_len(const struct sk_buff_head *l) { return l->qlen; }
static inline bool skb_queue_empty(const struct sk_buff_head *l) { return l->next == (const struct sk_buff *)l; }
static inline struct sk_buff *skb_peek(const struct sk_buff_head *l)
{ struct sk_buff *s = l->next; return s == (const struct sk_buff *)l ? NULL : s; }
static inline struct sk_buff *skb_peek_tail(const struct sk_buff_head *l)
{ struct sk_buff *s = l->prev; return s == (const struct sk_buff *)l ? NULL : s; }
static inline void __skb_insert(struct sk_buff *n, struct sk_buff *prev, struct sk_buff *next, struct sk_buff_head *l)
{ n->next = next; n->prev = prev; next->prev = n; prev->next = n; l->qlen++; }
static inline void __skb_queue_tail(struct sk_buff_head *l, struct sk_buff *n)
{ __skb_insert(n, l->prev, (struct sk_buff *)l, l); }
static inline void __skb_queue_head(struct sk_buff_head *l, struct sk_buff *n)
{ __skb_insert(n, (struct sk_buff *)l, l->next, l); }
#define skb_queue_tail __skb_queue_tail
#define skb_queue_head __skb_queue_head
static inline void __skb_unlink(struct sk_buff *s, struct sk_buff_head *l)
{ struct sk_buff *n = s->next, *p = s->prev; l->qlen--; s->next = s->prev = NULL; n->prev = p; p->next = n; }
#define skb_unlink __skb_unlink
static inline struct sk_buff *__skb_dequeue(struct sk_buff_head *l)
{ struct sk_buff *s = skb_peek(l); if (s) __skb_unlink(s, l); return s; }
#define skb_dequeue __skb_dequeue
static inline void __skb_queue_purge(struct sk_buff_head *l)
{ struct sk_buff *s; while ((s = __skb_dequeue(l)) != NULL) kshim_free_skb(s); }
#define skb_queue_purge __skb_queue_purge
static inline void skb_queue_splice_tail_init(struct sk_buff_head *l, struct sk_buff_head *h)
{ struct sk_buff *s; while ((s = __skb_dequeue(l)) != NULL) __skb_queue_tail(h, s); }
#define skb_queue_splice_init(l, h) skb_queue_splice_tail_init(l, h)
#define skb_queue_walk(q, s) for (s = (q)->next; s != (struct sk_buff *)(q); s = s->next)
#define skb_queue_walk_safe(q, s, t) for (s = (q)->next, t = s->next; s != (struct sk_buff *)(q); s = t, t = s->next)
#define skb_list_walk_safe(first, s, n) for ((s) = (first), (n) = (s) ? (s)->next : NULL; (s); (s) = (n), (n) = (s) ? (s)->next : NULL)

#endif
