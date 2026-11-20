/* SPDX-License-Identifier: ISC */
/*
 * Userspace shim of the Linux kernel / mac80211 API surface that the mt76 headers and the
 * receive-path sources (mt76x02_mac.c) need, so the UNMODIFIED driver sources compile and run in
 * a fuzz harness. Every kernel header the driver includes (linux/*.h, net/*.h) resolves to this
 * file via mayhem/kshim/include/.
 *
 * What is real here: the data-path helpers the RX code calls on attacker-controlled bytes
 * (sk_buff data/len handling, skb_pull/trim/push, bitfield accessors, endianness, the 802.11
 * header helpers ieee80211_get_hdrlen_from_skb & co.). They follow the kernel's semantics,
 * including its bounds behaviour, so a bug in the driver shows up as an ASan report instead
 * of being masked by a too-forgiving shim.
 *
 * What is a stand-in: locks, RCU, workqueues, NAPI, DMA, USB, LEDs, WED, page_pool and the
 * rest of the device plumbing the driver's structs embed. Those are opaque/dummy types; the
 * functions that would touch hardware are stubs (mayhem/kshim/kstubs.c) that abort loudly if
 * the fuzzed path ever reaches them.
 */
#ifndef MT76_KSHIM_H
#define MT76_KSHIM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>

/* ---------------------------------------------------------------- basic types */
typedef uint8_t u8;   typedef int8_t s8;
typedef uint16_t u16; typedef int16_t s16;
typedef uint32_t u32; typedef int32_t s32;
typedef uint64_t u64; typedef int64_t s64;
typedef uint8_t __u8; typedef int8_t __s8;
typedef uint16_t __u16; typedef int16_t __s16;
typedef uint32_t __u32; typedef int32_t __s32;
typedef uint64_t __u64; typedef int64_t __s64;
typedef uint16_t __le16; typedef uint32_t __le32; typedef uint64_t __le64;
typedef uint16_t __be16; typedef uint32_t __be32; typedef uint64_t __be64;
typedef uint16_t __sum16; typedef uint32_t __wsum;
typedef uint64_t dma_addr_t;
typedef uint64_t phys_addr_t;
typedef uint64_t resource_size_t;
typedef unsigned int gfp_t;
typedef int64_t ktime_t;
typedef long ssize_t_k;
typedef int irqreturn_t;
typedef struct { int counter; } atomic_t;
typedef struct { long counter; } atomic_long_t;
typedef struct { s64 counter; } atomic64_t;
typedef struct { int v; } spinlock_t;
typedef struct { int v; } rwlock_t;
typedef struct { int v; } wait_queue_head_t;
typedef struct { int v; } seqlock_t;
typedef unsigned long kernel_ulong_t;

#define __iomem
#define __rcu
#define __force
#define __user
#define __bitwise
#define __must_check
#define __maybe_unused __attribute__((unused))
#define __always_unused __attribute__((unused))
#define __packed __attribute__((packed))
#define __aligned(x) __attribute__((aligned(x)))
#define __always_inline inline __attribute__((always_inline))
#define noinline __attribute__((noinline))
#define __cold
#define __printf(a, b) __attribute__((format(printf, a, b)))
#define __counted_by(x)
#define __nonstring
#define __randomize_layout
#define __acquires(x)
#define __releases(x)
#define __must_hold(x)
#define __init
#define __exit
#define __initdata
#define __read_mostly
#define __ro_after_init
#define __stringify_1(x) #x
#define __stringify(x) __stringify_1(x)
#define fallthrough __attribute__((fallthrough))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define smp_store_release(p, v) (*(p) = (v))
#define smp_load_acquire(p) (*(p))
#define WRITE_ONCE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))
#define barrier() __asm__ __volatile__("" ::: "memory")
#define wmb() barrier()
#define rmb() barrier()
#define mb() barrier()
#define dma_rmb() barrier()
#define dma_wmb() barrier()
#define smp_wmb() barrier()
#define smp_rmb() barrier()
#define smp_mb() barrier()
#define smp_mb__before_atomic() barrier()
#define smp_mb__after_atomic() barrier()

#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define EXPORT_SYMBOL_NS_GPL(x, ns)
#define MODULE_LICENSE(x)
#define MODULE_AUTHOR(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_FIRMWARE(x)
#define MODULE_DEVICE_TABLE(a, b)
#define module_param(a, b, c)
#define module_param_named(a, b, c, d)
#define MODULE_PARM_DESC(a, b)
#define module_init(x)
#define module_exit(x)
#define THIS_MODULE NULL

/* ---------------------------------------------------------------- arithmetic helpers */
#define BITS_PER_LONG 64
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#define GENMASK(h, l) (((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define GENMASK_ULL(h, l) (((~0ULL) - (1ULL << (l)) + 1) & (~0ULL >> (63 - (h))))
#define BITS_TO_LONGS(n) (((n) + BITS_PER_LONG - 1) / BITS_PER_LONG)
#define DECLARE_BITMAP(name, bits) unsigned long name[BITS_TO_LONGS(bits)]
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define sizeof_field(t, m) sizeof(((t *)0)->m)
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define container_of_const container_of
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min3(a, b, c) min(min(a, b), c)
#define max3(a, b, c) max(max(a, b), c)
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define clamp(v, lo, hi) min(max(v, lo), hi)
#define clamp_t(t, v, lo, hi) min_t(t, max_t(t, v, lo), hi)
#define clamp_val(v, lo, hi) clamp_t(__typeof__(v), v, lo, hi)
#define swap(a, b) do { __typeof__(a) __t = (a); (a) = (b); (b) = __t; } while (0)
#define abs(x) __builtin_abs(x)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define DIV_ROUND_CLOSEST(x, d) (((x) + ((d) / 2)) / (d))
#define ALIGN(x, a) (((x) + ((a) - 1)) & ~((__typeof__(x))(a) - 1))
#define IS_ALIGNED(x, a) (((x) & ((__typeof__(x))(a) - 1)) == 0)
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define round_up(x, y) ((((x) - 1) | ((__typeof__(x))((y) - 1))) + 1)
#define rounddown(x, y) ((x) - ((x) % (y)))
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define IS_ENABLED(x) 0
#define IS_BUILTIN(x) 0
#define IS_MODULE(x) 0
#define IS_REACHABLE(x) 0
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-4095)
#define BUILD_BUG_ON(c) _Static_assert(!(c), "BUILD_BUG_ON")
#define BUILD_BUG_ON_ZERO(c) 0
#define __is_constexpr(x) 0
#define struct_size(p, member, n) (sizeof(*(p)) + sizeof(*(p)->member) * (n))
#define flex_array_size(p, member, n) (sizeof(*(p)->member) * (n))
#define typecheck(t, x) 1
#define do_div(n, base) ({ u32 __r = (n) % (base); (n) /= (base); __r; })
#define U8_MAX 0xff
#define S8_MAX 127
#define S8_MIN (-128)
#define U16_MAX 0xffff
#define U32_MAX 0xffffffffU
#define S32_MAX 0x7fffffff
#define HZ 100
#define USEC_PER_SEC 1000000L
#define MSEC_PER_SEC 1000L
#define NSEC_PER_USEC 1000L
#define NSEC_PER_MSEC 1000000L
#define NSEC_PER_SEC 1000000000L
#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_P_PAE 0x888E
#define ETH_P_802_3 0x0001
#define ETH_P_IP 0x0800
#define ETH_P_80221 0x8917
#define MAX_ERRNO 4095
#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif
#define IFNAMSIZ 16
#define NUMA_NO_NODE (-1)
#define PAGE_SIZE 4096UL
#define PAGE_SHIFT 12
#define SMP_CACHE_BYTES 64
#define L1_CACHE_BYTES 64
#define NET_SKB_PAD 64
#define NET_IP_ALIGN 2

static inline int fls(unsigned int x) { return x ? 32 - __builtin_clz(x) : 0; }
static inline unsigned long __ffs(unsigned long x) { return __builtin_ctzl(x); }
static inline unsigned long __fls(unsigned long x) { return 63 - __builtin_clzl(x); }
static inline unsigned long ffz(unsigned long x) { return __builtin_ctzl(~x); }
static inline int hweight8(unsigned int w) { return __builtin_popcount(w & 0xff); }
static inline int hweight16(unsigned int w) { return __builtin_popcount(w & 0xffff); }
static inline int hweight32(unsigned int w) { return __builtin_popcount(w); }
static inline int hweight_long(unsigned long w) { return __builtin_popcountl(w); }
static inline int ilog2(u64 n) { return 63 - __builtin_clzll(n); }
static inline bool is_power_of_2(unsigned long n) { return n != 0 && ((n & (n - 1)) == 0); }
static inline unsigned long roundup_pow_of_two(unsigned long n) { return 1UL << (64 - __builtin_clzl(n - 1)); }
static inline u32 ror32(u32 w, unsigned int s) { return (w >> (s & 31)) | (w << ((-s) & 31)); }
static inline s32 sign_extend32(u32 value, int index) { u8 shift = 31 - index; return (s32)(value << shift) >> shift; }
static inline u64 div_u64(u64 a, u32 b) { return a / b; }
static inline s64 div_s64(s64 a, s32 b) { return a / b; }
static inline u64 div64_u64(u64 a, u64 b) { return a / b; }
static inline unsigned int jiffies_to_msecs(unsigned long j) { return j * 10; }
static inline unsigned long msecs_to_jiffies(unsigned int m) { return m / 10; }
static inline unsigned long usecs_to_jiffies(unsigned int u) { return u / 10000; }
extern unsigned long jiffies;
#define time_after(a, b) ((long)((b) - (a)) < 0)
#define time_before(a, b) time_after(b, a)
#define time_after32(a, b) ((s32)((u32)(b) - (u32)(a)) < 0)
#define time_before32(b, a) time_after32(a, b)
#define time_after_eq(a, b) ((long)((a) - (b)) >= 0)
#define time_is_after_jiffies(a) time_before(jiffies, a)
#define time_is_before_jiffies(a) time_after(jiffies, a)

/* bit ops on unsigned long bitmaps */
static inline bool test_bit(long nr, const volatile unsigned long *addr) { return (addr[nr / 64] >> (nr % 64)) & 1; }
static inline void set_bit(long nr, volatile unsigned long *addr) { addr[nr / 64] |= 1UL << (nr % 64); }
static inline void clear_bit(long nr, volatile unsigned long *addr) { addr[nr / 64] &= ~(1UL << (nr % 64)); }
static inline bool test_and_set_bit(long nr, volatile unsigned long *addr) { bool o = test_bit(nr, addr); set_bit(nr, addr); return o; }
static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr) { bool o = test_bit(nr, addr); clear_bit(nr, addr); return o; }
#define __set_bit set_bit
#define __clear_bit clear_bit
static inline void bitmap_zero(unsigned long *d, unsigned int n) { memset(d, 0, BITS_TO_LONGS(n) * sizeof(long)); }
static inline unsigned long find_first_zero_bit(const unsigned long *a, unsigned long size)
{ for (unsigned long i = 0; i < size; i++) if (!test_bit(i, a)) return i; return size; }
static inline unsigned long find_first_bit(const unsigned long *a, unsigned long size)
{ for (unsigned long i = 0; i < size; i++) if (test_bit(i, a)) return i; return size; }
static inline unsigned long find_next_bit(const unsigned long *a, unsigned long size, unsigned long off)
{ for (unsigned long i = off; i < size; i++) if (test_bit(i, a)) return i; return size; }
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size)); (bit) < (size); (bit) = find_next_bit((addr), (size), (bit) + 1))

/* ---------------------------------------------------------------- bitfield.h */
#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define FIELD_GET(mask, reg) ((__typeof__(mask))(((reg) & (mask)) >> __bf_shf(mask)))
#define FIELD_PREP(mask, val) ((((__typeof__(mask))(val)) << __bf_shf(mask)) & (mask))
#define FIELD_FIT(mask, val) (!((((__typeof__(mask))(val)) << __bf_shf(mask)) & ~(mask)))
#define FIELD_MAX(mask) ((__typeof__(mask))((mask) >> __bf_shf(mask)))
#define u8_get_bits(v, m) ((u8)FIELD_GET(m, v))
#define u16_get_bits(v, m) ((u16)FIELD_GET(m, v))
#define u32_get_bits(v, m) ((u32)FIELD_GET(m, v))
#define u32_encode_bits(v, m) ((u32)FIELD_PREP(m, v))
#define u16_encode_bits(v, m) ((u16)FIELD_PREP(m, v))
#define u8_encode_bits(v, m) ((u8)FIELD_PREP(m, v))
#define le16_get_bits(v, m) ((u16)FIELD_GET(m, le16_to_cpu(v)))
#define le32_get_bits(v, m) ((u32)FIELD_GET(m, le32_to_cpu(v)))
#define le64_get_bits(v, m) ((u64)FIELD_GET(m, le64_to_cpu(v)))
#define le16_encode_bits(v, m) cpu_to_le16(FIELD_PREP(m, v))
#define le32_encode_bits(v, m) cpu_to_le32(FIELD_PREP(m, v))
#define le64_encode_bits(v, m) cpu_to_le64(FIELD_PREP(m, v))
#define u32p_replace_bits(p, v, m) (*(p) = (*(p) & ~(m)) | FIELD_PREP(m, v))
#define u32_replace_bits(o, v, m) (((o) & ~(m)) | FIELD_PREP(m, v))
#define le32p_replace_bits(p, v, m) (*(p) = cpu_to_le32((le32_to_cpu(*(p)) & ~(m)) | FIELD_PREP(m, v)))

/* ---------------------------------------------------------------- endianness (x86-64: LE) */
#define cpu_to_le16(x) ((__le16)(u16)(x))
#define cpu_to_le32(x) ((__le32)(u32)(x))
#define cpu_to_le64(x) ((__le64)(u64)(x))
#define le16_to_cpu(x) ((u16)(__le16)(x))
#define le32_to_cpu(x) ((u32)(__le32)(x))
#define le64_to_cpu(x) ((u64)(__le64)(x))
#define cpu_to_be16(x) ((__be16)__builtin_bswap16(x))
#define cpu_to_be32(x) ((__be32)__builtin_bswap32(x))
#define be16_to_cpu(x) __builtin_bswap16((u16)(x))
#define be32_to_cpu(x) __builtin_bswap32((u32)(x))
#define htons(x) cpu_to_be16(x)
#define ntohs(x) be16_to_cpu(x)
#define le16_add_cpu(p, v) (*(p) = cpu_to_le16(le16_to_cpu(*(p)) + (v)))
#define le32_add_cpu(p, v) (*(p) = cpu_to_le32(le32_to_cpu(*(p)) + (v)))
#define le32_to_cpup(p) le32_to_cpu(*(const __le32 *)(p))
#define le16_to_cpup(p) le16_to_cpu(*(const __le16 *)(p))
static inline u16 get_unaligned_le16(const void *p) { u16 v; memcpy(&v, p, 2); return v; }
static inline u32 get_unaligned_le32(const void *p) { u32 v; memcpy(&v, p, 4); return v; }
static inline u64 get_unaligned_le64(const void *p) { u64 v; memcpy(&v, p, 8); return v; }
static inline u16 get_unaligned_be16(const void *p) { u16 v; memcpy(&v, p, 2); return __builtin_bswap16(v); }
static inline u32 get_unaligned_be32(const void *p) { u32 v; memcpy(&v, p, 4); return __builtin_bswap32(v); }
static inline void put_unaligned_le16(u16 v, void *p) { memcpy(p, &v, 2); }
static inline void put_unaligned_le32(u32 v, void *p) { memcpy(p, &v, 4); }
static inline void put_unaligned_le64(u64 v, void *p) { memcpy(p, &v, 8); }
#define get_unaligned(p) ({ __typeof__(*(p)) __v; memcpy(&__v, (p), sizeof(__v)); __v; })
#define put_unaligned(v, p) do { __typeof__(*(p)) __v = (v); memcpy((p), &__v, sizeof(__v)); } while (0)

/* ---------------------------------------------------------------- diagnostics */
/* WARN_ON in the kernel prints a splat and continues: keep it non-fatal, but visible. */
#define WARN_ON(c) ({ int __c = !!(c); if (__c) fprintf(stderr, "WARN_ON(%s) %s:%d\n", #c, __FILE__, __LINE__); __c; })
#define WARN_ON_ONCE(c) WARN_ON(c)
#define WARN(c, ...) WARN_ON(c)
#define WARN_ONCE(c, ...) WARN_ON(c)
#define BUG_ON(c) do { if (c) abort(); } while (0)
#define BUG() abort()
#define pr_fmt(fmt) fmt
#define printk(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_warn(...) ((void)0)
#define pr_info(...) ((void)0)
#define pr_debug(...) ((void)0)
#define pr_err_ratelimited(...) ((void)0)
#define pr_warn_once(...) ((void)0)
#define dev_err(d, ...) ((void)(d))
#define dev_warn(d, ...) ((void)(d))
#define dev_info(d, ...) ((void)(d))
#define dev_dbg(d, ...) ((void)(d))
#define dev_notice(d, ...) ((void)(d))
#define dev_err_ratelimited(d, ...) ((void)(d))
#define dev_warn_ratelimited(d, ...) ((void)(d))
#define dev_err_once(d, ...) ((void)(d))
#define dev_warn_once(d, ...) ((void)(d))
#define dev_err_probe(d, e, ...) (e)
#define wiphy_err(w, ...) ((void)(w))
#define wiphy_warn(w, ...) ((void)(w))
#define wiphy_info(w, ...) ((void)(w))
#define wiphy_dbg(w, ...) ((void)(w))
#define net_ratelimit() 0
#define might_sleep() ((void)0)
#define lockdep_assert_held(l) ((void)(l))
#define lockdep_assert_not_held(l) ((void)(l))
#define lockdep_is_held(l) 1
#define lockdep_assert_wiphy(w) ((void)(w))

/* ---------------------------------------------------------------- ERR_PTR */
static inline void *ERR_PTR(long e) { return (void *)e; }
static inline long PTR_ERR(const void *p) { return (long)p; }
static inline bool IS_ERR(const void *p) { return IS_ERR_VALUE(p); }
static inline bool IS_ERR_OR_NULL(const void *p) { return !p || IS_ERR(p); }
static inline int PTR_ERR_OR_ZERO(const void *p) { return IS_ERR(p) ? (int)PTR_ERR(p) : 0; }

/* ---------------------------------------------------------------- lists */
struct list_head { struct list_head *next, *prev; };
struct hlist_node { struct hlist_node *next, **pprev; };
struct hlist_head { struct hlist_node *first; };
struct rcu_head { void *next; void (*func)(struct rcu_head *); };
#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)
static inline void INIT_LIST_HEAD(struct list_head *l) { l->next = l; l->prev = l; }
static inline void __list_add(struct list_head *n, struct list_head *p, struct list_head *nx)
{ nx->prev = n; n->next = nx; n->prev = p; p->next = n; }
static inline void list_add(struct list_head *n, struct list_head *h) { __list_add(n, h, h->next); }
static inline void list_add_tail(struct list_head *n, struct list_head *h) { __list_add(n, h->prev, h); }
static inline void __list_del(struct list_head *p, struct list_head *n) { n->prev = p; p->next = n; }
static inline void list_del(struct list_head *e) { __list_del(e->prev, e->next); e->next = e->prev = NULL; }
static inline void list_del_init(struct list_head *e) { __list_del(e->prev, e->next); INIT_LIST_HEAD(e); }
static inline bool list_empty(const struct list_head *h) { return h->next == h; }
static inline void list_move_tail(struct list_head *e, struct list_head *h) { __list_del(e->prev, e->next); list_add_tail(e, h); }
static inline void list_splice_tail_init(struct list_head *l, struct list_head *h)
{ if (!list_empty(l)) { struct list_head *f = l->next, *la = l->prev, *at = h->prev; f->prev = at; at->next = f; la->next = h; h->prev = la; INIT_LIST_HEAD(l); } }
static inline void list_splice_init(struct list_head *l, struct list_head *h)
{ if (!list_empty(l)) { struct list_head *f = l->next, *la = l->prev, *at = h->next; f->prev = h; h->next = f; la->next = at; at->prev = la; INIT_LIST_HEAD(l); } }
#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) list_entry((ptr)->next, type, member)
#define list_first_entry_or_null(ptr, type, member) (list_empty(ptr) ? NULL : list_first_entry(ptr, type, member))
#define list_next_entry(pos, member) list_entry((pos)->member.next, __typeof__(*(pos)), member)
#define list_for_each_entry(pos, head, member) \
	for (pos = list_first_entry(head, __typeof__(*pos), member); &pos->member != (head); pos = list_next_entry(pos, member))
#define list_for_each_entry_safe(pos, n, head, member) \
	for (pos = list_first_entry(head, __typeof__(*pos), member), n = list_next_entry(pos, member); \
	     &pos->member != (head); pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_rcu(pos, head, member, ...) list_for_each_entry(pos, head, member)
#define list_add_tail_rcu list_add_tail
#define list_del_rcu list_del
#define hlist_for_each_entry(pos, head, member) for (pos = NULL; pos; )

/* ---------------------------------------------------------------- locking / RCU (single thread) */
struct mutex { int v; };
struct lock_class_key { int v; };
struct completion { int done; };
#define DEFINE_MUTEX(m) struct mutex m
#define spin_lock_init(l) ((void)(l))
#define spin_lock(l) ((void)(l))
#define spin_unlock(l) ((void)(l))
#define spin_lock_bh(l) ((void)(l))
#define spin_unlock_bh(l) ((void)(l))
#define spin_lock_irq(l) ((void)(l))
#define spin_unlock_irq(l) ((void)(l))
#define spin_lock_irqsave(l, f) ((void)(l), (f) = 0)
#define spin_unlock_irqrestore(l, f) ((void)(l), (void)(f))
#define spin_trylock(l) 1
#define mutex_init(m) ((void)(m))
#define mutex_lock(m) ((void)(m))
#define mutex_unlock(m) ((void)(m))
#define mutex_destroy(m) ((void)(m))
#define mutex_is_locked(m) 1
#define local_bh_disable() ((void)0)
#define local_bh_enable() ((void)0)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(p) (p)
#define rcu_dereference_protected(p, c) (p)
#define rcu_dereference_check(p, c) (p)
#define rcu_access_pointer(p) (p)
#define rcu_assign_pointer(p, v) ((p) = (v))
#define RCU_INIT_POINTER(p, v) ((p) = (v))
#define rcu_replace_pointer(rp, p, c) ({ __typeof__(rp) __o = (rp); (rp) = (p); __o; })
#define synchronize_rcu() ((void)0)
#define kfree_rcu(p, f) free(p)
#define init_completion(c) ((c)->done = 0)
#define reinit_completion(c) ((c)->done = 0)
#define complete(c) ((c)->done = 1)
#define init_waitqueue_head(w) ((void)(w))
#define wake_up(w) ((void)(w))
#define wake_up_process(t) ((void)(t))
#define atomic_read(a) ((a)->counter)
#define atomic_set(a, v) ((a)->counter = (v))
#define atomic_inc(a) ((void)(a)->counter++)
#define atomic_dec(a) ((void)(a)->counter--)
#define atomic_add(v, a) ((a)->counter += (v))
#define atomic_sub(v, a) ((a)->counter -= (v))
#define atomic_inc_return(a) (++(a)->counter)
#define atomic_dec_return(a) (--(a)->counter)
#define atomic_dec_and_test(a) (--(a)->counter == 0)
#define atomic_add_return(v, a) ((a)->counter += (v))
#define atomic_cmpxchg(a, o, n) ({ int __o = (a)->counter; if (__o == (o)) (a)->counter = (n); __o; })
#define atomic_xchg(a, n) ({ int __o = (a)->counter; (a)->counter = (n); __o; })

/* ---------------------------------------------------------------- deferred work (never run) */
struct work_struct { void (*func)(struct work_struct *); };
struct timer_list { void (*function)(struct timer_list *); unsigned long expires; };
struct delayed_work { struct work_struct work; struct timer_list timer; };
struct workqueue_struct { int v; };
struct tasklet_struct { void (*callback)(struct tasklet_struct *); };
struct hrtimer { int v; };
struct task_struct { int v; };
struct kthread_worker { int v; };
#define INIT_WORK(w, f) ((w)->func = (f))
#define INIT_DELAYED_WORK(w, f) ((w)->work.func = (f))
#define to_delayed_work(w) container_of(w, struct delayed_work, work)
#define from_tasklet(var, t, field) container_of(t, __typeof__(*var), field)
#define from_timer(var, t, field) container_of(t, __typeof__(*var), field)
#define timer_container_of(var, t, field) container_of(t, __typeof__(*var), field)
#define schedule_work(w) ((void)(w), true)
#define queue_work(q, w) ((void)(q), (void)(w), true)
#define cancel_work_sync(w) ((void)(w), false)
#define cancel_delayed_work_sync(w) ((void)(w), false)
#define cancel_delayed_work(w) ((void)(w), false)
#define disable_delayed_work_sync(w) ((void)(w), false)
#define enable_delayed_work(w) ((void)(w), true)
#define flush_work(w) ((void)(w))
#define tasklet_schedule(t) ((void)(t))
#define tasklet_disable(t) ((void)(t))
#define tasklet_enable(t) ((void)(t))
#define tasklet_kill(t) ((void)(t))
#define tasklet_setup(t, f) ((t)->callback = (f))
#define timer_setup(t, f, fl) ((t)->function = (f))
#define mod_timer(t, e) ((void)(t), 0)
#define del_timer_sync(t) ((void)(t), 0)
#define timer_delete_sync(t) ((void)(t), 0)
#define usleep_range(a, b) ((void)0)
#define msleep(a) ((void)0)
#define udelay(a) ((void)0)
#define mdelay(a) ((void)0)
#define cond_resched() ((void)0)
#define kthread_should_stop() true
#define kthread_should_park() false
#define kthread_parkme() ((void)0)
#define set_current_state(s) ((void)0)
#define schedule() ((void)0)
#define TASK_INTERRUPTIBLE 1
#define TASK_RUNNING 0

/* ---------------------------------------------------------------- memory */
#define GFP_KERNEL 0u
#define GFP_ATOMIC 1u
#define GFP_DMA32 2u
#define __GFP_NOWARN 4u
#define __GFP_ZERO 8u
static inline void *kmalloc(size_t n, gfp_t f) { return (f & __GFP_ZERO) ? calloc(1, n) : malloc(n); }
static inline void *kzalloc(size_t n, gfp_t f) { (void)f; return calloc(1, n); }
static inline void *kcalloc(size_t n, size_t s, gfp_t f) { (void)f; return calloc(n, s); }
static inline void *kmemdup(const void *p, size_t n, gfp_t f) { void *d = malloc(n); (void)f; if (d) memcpy(d, p, n); return d; }
static inline void kfree(const void *p) { free((void *)p); }
static inline void *vzalloc(size_t n) { return calloc(1, n); }
static inline void vfree(const void *p) { free((void *)p); }
#define kfree_sensitive kfree
#define devm_kzalloc(d, n, f) kzalloc(n, f)
#define devm_kcalloc(d, n, s, f) kcalloc(n, s, f)
#define devm_kmalloc(d, n, f) kmalloc(n, f)
#define devm_kmemdup(d, p, n, f) kmemdup(p, n, f)
#define devm_kfree(d, p) kfree(p)
static inline size_t strscpy(char *d, const char *s, size_t n)
{ size_t l = strnlen(s, n); if (n == 0) return -E2BIG; if (l >= n) l = n - 1; memcpy(d, s, l); d[l] = 0; return l; }
#define strscpy_pad strscpy
#define get_random_u32() 4u
#define get_random_u8() 4u
#define prandom_u32_max(n) 0u
#define get_random_bytes(p, n) memset((p), 4, (n))

/* ---------------------------------------------------------------- devices (opaque) */
struct device { void *driver_data; const char *name; struct device_node *of_node; };
struct device_node { int v; };
struct module { int v; };
struct dentry { int v; };
struct seq_file { void *private; };
struct file_operations { int v; };
struct debugfs_blob_wrapper { void *data; unsigned long size; };
struct regmap { int v; };
struct pci_dev { struct device dev; };
struct sdio_func { struct device dev; };
struct usb_device { struct device dev; };
struct usb_interface { struct device dev; };
struct usb_sg_request { int v; };
struct urb { void *context; int status; unsigned int actual_length; unsigned int num_sgs; void *transfer_buffer; struct scatterlist *sg; };
struct scatterlist { unsigned long page_link; unsigned int offset, length; dma_addr_t dma_address; };
enum led_brightness { LED_OFF = 0, LED_FULL = 255 };
struct led_classdev { const char *name; int (*blink_set)(struct led_classdev *, unsigned long *, unsigned long *);
	void (*brightness_set)(struct led_classdev *, enum led_brightness);
	int (*brightness_set_blocking)(struct led_classdev *, enum led_brightness); const char *default_trigger; };
struct firmware { size_t size; const u8 *data; };
struct idr { int v; };
struct ida { int v; };
struct net_device { char name[IFNAMSIZ]; };
struct napi_struct { struct net_device *dev; };
struct page_pool;
struct page { struct page_pool *pp; void *addr; };
struct page_pool { int v; };
struct mtk_wed_device { int v; };
struct mtk_wed_bm_desc { int v; };
struct mtk_wed_wo_rx_stats { int v; };
struct mtk_wed_ring { int v; };
struct cpumask { int v; };
struct notifier_block { int v; };
struct thermal_cooling_device { int v; };
struct mtk_wed_hw { int v; };
struct airoha_npu_core { int v; };
struct airoha_foe_stats { int v; };
struct cfg80211_flow_info { int v; };
#define dev_get_drvdata(d) ((d)->driver_data)
#define dev_set_drvdata(d, p) ((d)->driver_data = (p))
#define dev_name(d) "mt76-shim"
#define of_property_read_bool(n, p) false
#define of_property_read_u32(n, p, v) (-EINVAL)
#define of_node_put(n) ((void)(n))
static inline bool mtk_wed_device_active(struct mtk_wed_device *d) { (void)d; return false; }
#define mtk_wed_device_rx_release(dev, page) ((void)0)
#define mtk_wed_device_ppe_check(dev, skb, ...) ((void)0)	/* 4 args (mt7915), 5 (mt7996) */
#define mtk_wed_get_rx_capa(dev) false
#define mtk_wed_is_amsdu_supported(dev) false
#define mtk_wed_device_irq_get(dev, mask) 0
#define mtk_wed_device_irq_set_mask(dev, mask) ((void)0)
#define mtk_wed_device_start(dev, mask) ((void)0)
#define mtk_wed_device_detach(dev) ((void)0)
#define mtk_wed_device_dma_reset(dev) ((void)0)
#define mtk_wed_device_reset(dev) ((void)0)
#define mtk_wed_device_stop(dev) ((void)0)
#define mtk_wed_device_update_msg(dev, id, data, len) (-ENODEV)
#define MTK_WED_TX_QUEUES 2
#define MTK_WED_RX_QUEUES 2
#define MTK_WED_RX_PAGE_QUEUES 3
#define MTK_WED_WO_RXBM_IDX 0

/* io: mmio is never mapped in the shim; the bus ops in struct mt76_bus_ops are harness-provided */
static inline u32 readl(const volatile void __iomem *a) { (void)a; return 0; }
static inline void writel(u32 v, volatile void __iomem *a) { (void)v; (void)a; }
#define ioread32(a) readl(a)
#define iowrite32(v, a) writel(v, a)
#define memcpy_toio(d, s, n) ((void)0)
#define memcpy_fromio(d, s, n) memset((d), 0, (n))
#define memset_io(d, c, n) ((void)0)
#define readl_poll_timeout(...) 0

/* DMA (never mapped) */
enum dma_data_direction { DMA_BIDIRECTIONAL = 0, DMA_TO_DEVICE = 1, DMA_FROM_DEVICE = 2, DMA_NONE = 3 };
#define DMA_ATTR_SKIP_CPU_SYNC 0
#define dma_map_single(d, p, s, dir) ((dma_addr_t)(uintptr_t)(p))
#define dma_unmap_single(d, a, s, dir) ((void)0)
#define dma_mapping_error(d, a) 0
#define dma_sync_single_for_cpu(d, a, s, dir) ((void)0)
#define dma_sync_single_for_device(d, a, s, dir) ((void)0)
#define dmam_alloc_coherent(d, s, h, f) NULL
#define dma_alloc_coherent(d, s, h, f) NULL
#define dma_free_coherent(d, s, p, h) ((void)0)

/* ---------------------------------------------------------------- average.h (EWMA) */
#define DECLARE_EWMA(name, _precision, _weight_rcp)					\
	struct ewma_##name { unsigned long internal; };					\
	static inline void ewma_##name##_init(struct ewma_##name *e) { e->internal = 0; }	\
	static inline unsigned long ewma_##name##_read(struct ewma_##name *e)		\
	{ return e->internal >> (_precision); }						\
	static inline void ewma_##name##_add(struct ewma_##name *e, unsigned long val)	\
	{										\
		unsigned long internal = READ_ONCE(e->internal);			\
		unsigned long weight_rcp = ilog2(_weight_rcp);				\
		unsigned long precision = _precision;					\
		WRITE_ONCE(e->internal, internal ?					\
			(((internal << weight_rcp) - internal) + (val << precision)) >> weight_rcp : \
			(val << precision));						\
	}

/* ---------------------------------------------------------------- kfifo (pointer form only) */
#define DECLARE_KFIFO_PTR(fifo, type) struct { type *buf; unsigned int in, out, mask; } fifo
#define kfifo_alloc(fifo, size, gfp) 0
#define kfifo_free(fifo) ((void)0)
#define kfifo_put(fifo, val) ((void)(val), 0)
#define kfifo_get(fifo, val) 0
#define kfifo_reset(fifo) ((void)0)
#define kfifo_init(fifo, buf, size) 0

/* ---------------------------------------------------------------- tracepoints: compiled out */
#define TP_PROTO(args...) args
#define TP_ARGS(args...) args
#define TP_STRUCT__entry(args...)
#define TP_fast_assign(args...)
#define TP_printk(args...)
#define DECLARE_EVENT_CLASS(name, proto, args, tstruct, assign, print)
#define DEFINE_EVENT(template, name, proto, args) static inline void trace_##name(proto) {}
#define TRACE_EVENT(name, proto, args, struct, assign, print) static inline void trace_##name(proto) {}

/* ---------------------------------------------------------------- netlink (opaque) */
struct nlattr { u16 nla_len; u16 nla_type; };
struct nla_policy { u8 type; u8 validation_type; u16 len; };
struct netlink_callback { long args[6]; };
struct netlink_ext_ack { const char *msg; };
#define NLA_ALIGNTO 4
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
static inline void *nla_data(const struct nlattr *nla) { return (char *)nla + NLA_HDRLEN; }
static inline int nla_len(const struct nlattr *nla) { return nla->nla_len - NLA_HDRLEN; }
static inline u8 nla_get_u8(const struct nlattr *nla) { return *(u8 *)nla_data(nla); }
static inline u32 nla_get_u32(const struct nlattr *nla) { u32 v; memcpy(&v, nla_data(nla), 4); return v; }
#define NLA_U8 1
#define NLA_U16 2
#define NLA_U32 3
#define NLA_U64 4
#define NLA_NESTED 9
#define NLA_FLAG 6


/* ---------------------------------------------------------------- misc device plumbing (stubs) */
enum tc_setup_type { TC_SETUP_QDISC_MQPRIO = 0 };
struct page *kshim_virt_to_head_page(const void *p);
#define virt_to_head_page(p) kshim_virt_to_head_page(p)
#define page_address(pg) ((pg)->addr)
struct page *kshim_page_pool_alloc_frag(struct page_pool *pp, unsigned int *offset, unsigned int size, gfp_t gfp);
#define page_pool_alloc_frag kshim_page_pool_alloc_frag
void kshim_page_pool_put_full_page(struct page_pool *pp, struct page *page, bool allow_direct);
#define page_pool_put_full_page kshim_page_pool_put_full_page
#define to_usb_interface(d) container_of(d, struct usb_interface, dev)
#define interface_to_usbdev(i) ((struct usb_device *)NULL)
#define usb_rcvbulkpipe(u, ep) ((unsigned int)(ep) | 0x80u)
#define usb_sndbulkpipe(u, ep) ((unsigned int)(ep))
int kshim_usb_bulk_msg(struct usb_device *u, unsigned int pipe, void *data, int len, int *actual, int timeout);
#define usb_bulk_msg kshim_usb_bulk_msg
struct task_struct *kshim_kthread_run(int (*fn)(void *), void *data, const char *fmt, ...);
#define kthread_run kshim_kthread_run
#define kthread_stop(t) ((void)(t), 0)
#define kthread_park(t) ((void)(t), 0)
#define kthread_unpark(t) ((void)(t))
int kshim_idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp);
void *kshim_idr_remove(struct idr *idr, unsigned long id);
void *kshim_idr_find(const struct idr *idr, unsigned long id);
#define idr_alloc kshim_idr_alloc
#define idr_remove kshim_idr_remove
#define idr_find kshim_idr_find
#define idr_init(i) ((void)(i))
#define idr_is_empty(i) true
#define idr_destroy(i) ((void)(i))
#define idr_for_each_entry(idr, entry, id) for ((id) = 0, (entry) = NULL; (entry); )


#define atomic64_set(a, v) ((a)->counter = (v))
#define atomic64_read(a) ((a)->counter)
#define atomic64_inc_return(a) (++(a)->counter)
#define atomic64_inc(a) ((void)++(a)->counter)
#define atomic64_add(v, a) ((a)->counter += (v))
#define kfifo_is_full(fifo) 0
#define kfifo_len(fifo) 0
#define ktime_get_boottime() ((ktime_t)0)
#define ktime_get_boottime_ns() ((u64)0)
#define ktime_get() ((ktime_t)0)
#define ktime_get_ns() ((u64)0)
#define ktime_to_us(k) ((s64)(k) / 1000)
#define ktime_to_ns(k) ((s64)(k))
#define ktime_sub(a, b) ((a) - (b))
#define ktime_us_delta(a, b) (((a) - (b)) / 1000)
#define netdev_priv(nd) ((void *)((char *)(nd) + sizeof(struct net_device)))


#define struct_group_tagged(TAG, NAME, MEMBERS...) \
	union { struct { MEMBERS }; struct TAG { MEMBERS } NAME; }
#define struct_group(NAME, MEMBERS...) union { struct { MEMBERS }; struct { MEMBERS } NAME; }
#ifndef static_assert
#define static_assert(expr, ...) _Static_assert(expr, #expr)
#endif
#define ktime_to_ms(k) ((s64)(k) / 1000000)
#define regmap_update_bits(m, r, mask, v) ((void)(m), 0)
#define queue_delayed_work(q, w, d) ((void)(q), (void)(w), true)
#define mod_delayed_work(q, w, d) ((void)(q), (void)(w), true)
#define work_pending(w) false
#define delayed_work_pending(w) false
#define napi_schedule(n) ((void)(n))
#define dev_coredumpv(d, data, len, gfp) vfree(data)
#define ETH_P_IPX 0x8137
#define ETH_P_AARP 0x80F3
#define ETH_P_802_3_MIN 0x0600
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_TDLS 0x890D
int kshim_request_firmware(const struct firmware **fw, const char *name, struct device *dev);
#define request_firmware kshim_request_firmware
#define firmware_request_nowarn kshim_request_firmware
#define release_firmware(fw) ((void)(fw))

#define wait_event_timeout(wq, cond, t) ((cond) ? 1 : 0)


struct page_pool_params { int order; unsigned int flags; int nid; struct device *dev; struct napi_struct *napi;
	enum dma_data_direction dma_dir; unsigned int max_len; unsigned int offset; unsigned int pool_size; struct net_device *netdev; unsigned int queue_idx; };
#define PP_FLAG_DMA_MAP BIT(0)
#define PP_FLAG_DMA_SYNC_DEV BIT(1)
#define page_pool_create(p) ((struct page_pool *)ERR_PTR(-ENOMEM))
#define page_pool_destroy(p) ((void)(p))
#define xdp_rxq_info_reg(...) 0
#define sched_set_fifo_low(t) ((void)(t))
#define of_get_child_by_name(n, name) ((struct device_node *)NULL)
#define of_device_is_available(n) false
#define of_find_property(n, name, l) NULL
#define alloc_ordered_workqueue(fmt, flags, ...) ((struct workqueue_struct *)NULL)
#define destroy_workqueue(w) ((void)(w))
#define led_classdev_register(d, l) 0
#define led_classdev_unregister(l) ((void)(l))
#define devm_led_classdev_register(d, l) 0
#define WQ_HIGHPRI 0
#define WQ_MEM_RECLAIM 0
#define WQ_UNBOUND 0

#include "kshim_skb.h"
#include "kshim_mac80211.h"

#endif /* MT76_KSHIM_H */
