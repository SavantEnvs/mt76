/* SPDX-License-Identifier: ISC */
/*
 * mac80211 / cfg80211 / 802.11 subset for the mt76 userspace shim (included by kshim.h).
 * Frame-format helpers (ieee80211_hdrlen and the fc predicates) are written from IEEE 802.11
 * to match the kernel's include/linux/ieee80211.h behaviour; the rest are the types the mt76
 * structs embed, kept only as large as the driver's code needs.
 */
#ifndef MT76_KSHIM_MAC80211_H
#define MT76_KSHIM_MAC80211_H

#include <linux/nl80211.h>  /* UAPI enums (nl80211_band, nl80211_iftype, ...) from linux-libc-dev */

#define NUM_NL80211_BANDS (NL80211_BAND_LC + 1)
#define IEEE80211_MAX_CHAINS 4
#define IEEE80211_NUM_TIDS 16
#define IEEE80211_NUM_ACS 4
#define IEEE80211_MLD_MAX_NUM_LINKS 15
#define IEEE80211_MIN_AMPDU_BUF 0x8
#define IEEE80211_MAX_AMPDU_BUF_HT 0x40
#define IEEE80211_MAX_AMPDU_BUF 0x400
#define IEEE80211_HT_MPDU_DENSITY_4 5
#define IEEE80211_MAX_SSID_LEN 32
#define IEEE80211_TX_MAX_RATES 4
#define IEEE80211_TX_RATE_TABLE_SIZE 4
#define IEEE80211_SCTL_FRAG 0x000F
#define IEEE80211_SCTL_SEQ 0xFFF0
#define IEEE80211_SN_MASK ((IEEE80211_SCTL_SEQ) >> 4)
#define IEEE80211_MAX_SN IEEE80211_SN_MASK
#define IEEE80211_SN_MODULO (IEEE80211_MAX_SN + 1)
#define IEEE80211_CCMP_HDR_LEN 8
#define IEEE80211_CCMP_MIC_LEN 8
#define IEEE80211_CCMP_PN_LEN 6
#define IEEE80211_GCMP_HDR_LEN 8
#define IEEE80211_CMAC_PN_LEN 6
#define IEEE80211_GMAC_PN_LEN 6
#define IEEE80211_WEP_IV_LEN 4
#define IEEE80211_TKIP_IV_LEN 8
#define FCS_LEN 4

/* ---------------------------------------------------------------- frame control */
#define IEEE80211_FCTL_VERS 0x0003
#define IEEE80211_FCTL_FTYPE 0x000c
#define IEEE80211_FCTL_STYPE 0x00f0
#define IEEE80211_FCTL_TODS 0x0100
#define IEEE80211_FCTL_FROMDS 0x0200
#define IEEE80211_FCTL_MOREFRAGS 0x0400
#define IEEE80211_FCTL_RETRY 0x0800
#define IEEE80211_FCTL_PM 0x1000
#define IEEE80211_FCTL_MOREDATA 0x2000
#define IEEE80211_FCTL_PROTECTED 0x4000
#define IEEE80211_FCTL_ORDER 0x8000
#define IEEE80211_FCTL_CTL_EXT 0x0f00
#define IEEE80211_FTYPE_MGMT 0x0000
#define IEEE80211_FTYPE_CTL 0x0004
#define IEEE80211_FTYPE_DATA 0x0008
#define IEEE80211_FTYPE_EXT 0x000c
#define IEEE80211_STYPE_ASSOC_REQ 0x0000
#define IEEE80211_STYPE_PROBE_RESP 0x0050
#define IEEE80211_STYPE_BEACON 0x0080
#define IEEE80211_STYPE_ACTION 0x00D0
#define IEEE80211_STYPE_CTL_EXT 0x0060
#define IEEE80211_STYPE_BACK_REQ 0x0080
#define IEEE80211_STYPE_BACK 0x0090
#define IEEE80211_STYPE_PSPOLL 0x00A0
#define IEEE80211_STYPE_RTS 0x00B0
#define IEEE80211_STYPE_CTS 0x00C0
#define IEEE80211_STYPE_ACK 0x00D0
#define IEEE80211_STYPE_NULLFUNC 0x0040
#define IEEE80211_STYPE_QOS_DATA 0x0080
#define IEEE80211_STYPE_QOS_NULLFUNC 0x00C0
#define IEEE80211_QOS_CTL_LEN 2
#define IEEE80211_QOS_CTL_TID_MASK 0x000f
#define IEEE80211_QOS_CTL_EOSP 0x0010
#define IEEE80211_QOS_CTL_ACK_POLICY_MASK 0x0060
#define IEEE80211_QOS_CTL_ACK_POLICY_NOACK 0x0020
#define IEEE80211_QOS_CTL_A_MSDU_PRESENT 0x0080
#define IEEE80211_HT_CTL_LEN 4

struct ieee80211_hdr {
	__le16 frame_control;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctrl;
	u8 addr4[ETH_ALEN];
} __packed __aligned(2);

struct ieee80211_qos_hdr {
	__le16 frame_control;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctrl;
	__le16 qos_ctrl;
} __packed __aligned(2);

struct ieee80211_bar {
	__le16 frame_control;
	__le16 duration;
	u8 ra[ETH_ALEN];
	u8 ta[ETH_ALEN];
	__le16 control;
	__le16 start_seq_num;
} __packed;

static inline bool ieee80211_has_tods(__le16 fc) { return (fc & cpu_to_le16(IEEE80211_FCTL_TODS)) != 0; }
static inline bool ieee80211_has_fromds(__le16 fc) { return (fc & cpu_to_le16(IEEE80211_FCTL_FROMDS)) != 0; }
static inline bool ieee80211_has_a4(__le16 fc)
{ __le16 t = cpu_to_le16(IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS); return (fc & t) == t; }
static inline bool ieee80211_has_morefrags(__le16 fc) { return (fc & cpu_to_le16(IEEE80211_FCTL_MOREFRAGS)) != 0; }
static inline bool ieee80211_has_protected(__le16 fc) { return (fc & cpu_to_le16(IEEE80211_FCTL_PROTECTED)) != 0; }
static inline bool ieee80211_has_order(__le16 fc) { return (fc & cpu_to_le16(IEEE80211_FCTL_ORDER)) != 0; }
static inline bool ieee80211_has_pm(__le16 fc) { return (fc & cpu_to_le16(IEEE80211_FCTL_PM)) != 0; }
static inline bool ieee80211_is_mgmt(__le16 fc)
{ return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE)) == cpu_to_le16(IEEE80211_FTYPE_MGMT); }
static inline bool ieee80211_is_ctl(__le16 fc)
{ return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE)) == cpu_to_le16(IEEE80211_FTYPE_CTL); }
static inline bool ieee80211_is_data(__le16 fc)
{ return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE)) == cpu_to_le16(IEEE80211_FTYPE_DATA); }
static inline bool ieee80211_is_ext(__le16 fc)
{ return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE)) == cpu_to_le16(IEEE80211_FTYPE_EXT); }
static inline bool ieee80211_is_data_qos(__le16 fc)
{ return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_STYPE_QOS_DATA)) ==
	 cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA); }
static inline bool ieee80211_is_data_present(__le16 fc)
{ return (fc & cpu_to_le16(IEEE80211_FCTL_FTYPE | 0x40)) == cpu_to_le16(IEEE80211_FTYPE_DATA); }
#define _FC_IS(fc, t, s) (((fc) & cpu_to_le16(IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) == cpu_to_le16((t) | (s)))
static inline bool ieee80211_is_beacon(__le16 fc) { return _FC_IS(fc, IEEE80211_FTYPE_MGMT, IEEE80211_STYPE_BEACON); }
static inline bool ieee80211_is_probe_resp(__le16 fc) { return _FC_IS(fc, IEEE80211_FTYPE_MGMT, IEEE80211_STYPE_PROBE_RESP); }
static inline bool ieee80211_is_action(__le16 fc) { return _FC_IS(fc, IEEE80211_FTYPE_MGMT, IEEE80211_STYPE_ACTION); }
static inline bool ieee80211_is_back_req(__le16 fc) { return _FC_IS(fc, IEEE80211_FTYPE_CTL, IEEE80211_STYPE_BACK_REQ); }
static inline bool ieee80211_is_ctl_ext(__le16 fc) { return _FC_IS(fc, IEEE80211_FTYPE_CTL, IEEE80211_STYPE_CTL_EXT); }
static inline bool ieee80211_is_pspoll(__le16 fc) { return _FC_IS(fc, IEEE80211_FTYPE_CTL, IEEE80211_STYPE_PSPOLL); }
static inline bool ieee80211_is_qos_nullfunc(__le16 fc) { return _FC_IS(fc, IEEE80211_FTYPE_DATA, IEEE80211_STYPE_QOS_NULLFUNC); }
static inline bool ieee80211_is_nullfunc(__le16 fc) { return _FC_IS(fc, IEEE80211_FTYPE_DATA, IEEE80211_STYPE_NULLFUNC); }
static inline bool ieee80211_is_any_nullfunc(__le16 fc) { return ieee80211_is_nullfunc(fc) || ieee80211_is_qos_nullfunc(fc); }
static inline bool ieee80211_is_first_frag(__le16 seq_ctrl) { return !(seq_ctrl & cpu_to_le16(IEEE80211_SCTL_FRAG)); }
static inline bool ieee80211_is_frag(struct ieee80211_hdr *hdr)
{ return ieee80211_has_morefrags(hdr->frame_control) || (hdr->seq_ctrl & cpu_to_le16(IEEE80211_SCTL_FRAG)); }
static inline bool ieee80211_is_bufferable_mmpdu(struct sk_buff *skb) { (void)skb; return false; }
static inline bool ieee80211_is_robust_mgmt_frame(struct sk_buff *skb) { (void)skb; return false; }
static inline u16 ieee80211_sn_add(u16 sn1, u16 sn2) { return (sn1 + sn2) & IEEE80211_SN_MASK; }
static inline u16 ieee80211_sn_inc(u16 sn) { return ieee80211_sn_add(sn, 1); }
static inline u16 ieee80211_sn_sub(u16 sn1, u16 sn2) { return (sn1 - sn2) & IEEE80211_SN_MASK; }
static inline bool ieee80211_sn_less(u16 sn1, u16 sn2) { return ((sn1 - sn2) & IEEE80211_SN_MASK) > (IEEE80211_SN_MODULO >> 1); }
static inline u8 *ieee80211_get_qos_ctl(struct ieee80211_hdr *hdr)
{
	u8 *p = (u8 *)hdr;
	if (ieee80211_has_a4(hdr->frame_control))
		return p + 30;
	return p + 24;
}
static inline u8 *ieee80211_get_DA(struct ieee80211_hdr *hdr)
{ return ieee80211_has_tods(hdr->frame_control) ? hdr->addr3 : hdr->addr1; }
static inline u8 *ieee80211_get_SA(struct ieee80211_hdr *hdr)
{ if (ieee80211_has_a4(hdr->frame_control)) return hdr->addr4; if (ieee80211_has_fromds(hdr->frame_control)) return hdr->addr3; return hdr->addr2; }

/* net/wireless/util.c semantics */
static inline unsigned int ieee80211_hdrlen(__le16 fc)
{
	unsigned int hdrlen = 24;

	if (ieee80211_is_ext(fc)) {
		hdrlen = 4;
		goto out;
	}
	if (ieee80211_is_data(fc)) {
		if (ieee80211_has_a4(fc))
			hdrlen = 30;
		if (ieee80211_is_data_qos(fc)) {
			hdrlen += IEEE80211_QOS_CTL_LEN;
			if (ieee80211_has_order(fc))
				hdrlen += IEEE80211_HT_CTL_LEN;
		}
		goto out;
	}
	if (ieee80211_is_mgmt(fc)) {
		if (ieee80211_has_order(fc))
			hdrlen += IEEE80211_HT_CTL_LEN;
		goto out;
	}
	if (ieee80211_is_ctl(fc)) {
		/* ACK and CTS are 10 bytes, all others 16 */
		if ((fc & cpu_to_le16(0x00E0)) == cpu_to_le16(0x00C0) ||
		    (fc & cpu_to_le16(0x00F0)) == cpu_to_le16(0x00E0))
			hdrlen = 10;
		else
			hdrlen = 16;
	}
out:
	return hdrlen;
}

static inline unsigned int ieee80211_get_hdrlen_from_skb(const struct sk_buff *skb)
{
	const __le16 *fc = (const __le16 *)skb->data;
	unsigned int hdrlen;

	if (unlikely(skb->len < 10))
		return 0;
	hdrlen = ieee80211_hdrlen(*fc);
	if (unlikely(hdrlen > skb->len))
		return 0;
	return hdrlen;
}

static inline bool is_zero_ether_addr(const u8 *a) { static const u8 z[ETH_ALEN]; return !memcmp(a, z, ETH_ALEN); }
static inline bool is_multicast_ether_addr(const u8 *a) { return a[0] & 1; }
static inline bool is_broadcast_ether_addr(const u8 *a) { return (a[0] & a[1] & a[2] & a[3] & a[4] & a[5]) == 0xff; }
static inline bool is_unicast_ether_addr(const u8 *a) { return !is_multicast_ether_addr(a); }
static inline bool is_valid_ether_addr(const u8 *a) { return !is_multicast_ether_addr(a) && !is_zero_ether_addr(a); }
static inline void ether_addr_copy(u8 *d, const u8 *s) { memcpy(d, s, ETH_ALEN); }
static inline bool ether_addr_equal(const u8 *a, const u8 *b) { return !memcmp(a, b, ETH_ALEN); }
static inline void eth_zero_addr(u8 *a) { memset(a, 0, ETH_ALEN); }
static inline void eth_broadcast_addr(u8 *a) { memset(a, 0xff, ETH_ALEN); }
static inline void eth_random_addr(u8 *a) { memset(a, 0x02, ETH_ALEN); a[0] = 0x02; }
struct ethhdr { u8 h_dest[ETH_ALEN]; u8 h_source[ETH_ALEN]; __be16 h_proto; } __packed;
struct mac_address { u8 addr[ETH_ALEN]; };

/* ---------------------------------------------------------------- RX status */
enum mac80211_rx_flags {
	RX_FLAG_MMIC_ERROR = BIT(0),
	RX_FLAG_DECRYPTED = BIT(1),
	RX_FLAG_ONLY_MONITOR = BIT(2),
	RX_FLAG_MMIC_STRIPPED = BIT(3),
	RX_FLAG_IV_STRIPPED = BIT(4),
	RX_FLAG_FAILED_FCS_CRC = BIT(5),
	RX_FLAG_FAILED_PLCP_CRC = BIT(6),
	RX_FLAG_MACTIME_IS_RTAP_TS64 = BIT(7),
	RX_FLAG_NO_SIGNAL_VAL = BIT(8),
	RX_FLAG_AMPDU_DETAILS = BIT(9),
	RX_FLAG_PN_VALIDATED = BIT(10),
	RX_FLAG_DUP_VALIDATED = BIT(11),
	RX_FLAG_AMPDU_LAST_KNOWN = BIT(12),
	RX_FLAG_AMPDU_IS_LAST = BIT(13),
	RX_FLAG_AMPDU_DELIM_CRC_ERROR = BIT(14),
	RX_FLAG_MACTIME = BIT(16) | BIT(17),
	RX_FLAG_MACTIME_START = 2 << 16,
	RX_FLAG_MACTIME_END = 3 << 16,
	RX_FLAG_SKIP_MONITOR = BIT(18),
	RX_FLAG_AMSDU_MORE = BIT(19),
	RX_FLAG_RADIOTAP_TLV_AT_END = BIT(20),
	RX_FLAG_MIC_STRIPPED = BIT(21),
	RX_FLAG_ALLOW_SAME_PN = BIT(22),
	RX_FLAG_ICV_STRIPPED = BIT(23),
	RX_FLAG_AMPDU_EOF_BIT = BIT(24),
	RX_FLAG_AMPDU_EOF_BIT_KNOWN = BIT(25),
	RX_FLAG_RADIOTAP_HE = BIT(26),
	RX_FLAG_RADIOTAP_HE_MU = BIT(27),
	RX_FLAG_RADIOTAP_LSIG = BIT(28),
	RX_FLAG_NO_PSDU = BIT(29),
	RX_FLAG_8023 = BIT(30),
};
enum mac80211_rx_encoding_flags {
	RX_ENC_FLAG_SHORTPRE = BIT(0),
	RX_ENC_FLAG_SHORT_GI = BIT(2),
	RX_ENC_FLAG_HT_GF = BIT(3),
	RX_ENC_FLAG_STBC_MASK = BIT(4) | BIT(5),
	RX_ENC_FLAG_LDPC = BIT(6),
	RX_ENC_FLAG_BF = BIT(7),
};
#define RX_ENC_FLAG_STBC_SHIFT 4
enum mac80211_rx_encoding { RX_ENC_LEGACY = 0, RX_ENC_HT, RX_ENC_VHT, RX_ENC_HE, RX_ENC_EHT };
enum rate_info_bw {
	RATE_INFO_BW_20 = 0, RATE_INFO_BW_5, RATE_INFO_BW_10, RATE_INFO_BW_40, RATE_INFO_BW_80,
	RATE_INFO_BW_160, RATE_INFO_BW_HE_RU, RATE_INFO_BW_320, RATE_INFO_BW_EHT_RU, RATE_INFO_BW_1, RATE_INFO_BW_2,
	RATE_INFO_BW_4, RATE_INFO_BW_8, RATE_INFO_BW_16,
};
enum nl80211_he_gi_k { NL80211_RATE_INFO_HE_GI_0_8_K };
struct ieee80211_rx_status {
	u64 mactime; u64 boottime_ns; u32 device_timestamp; u32 ampdu_reference; u32 flag;
	u16 freq: 13, freq_offset: 1; u8 enc_flags; u8 encoding: 3, bw: 4;
	union { struct { u8 he_ru: 3, he_gi: 2, he_dcm: 1; }; struct { u8 ru: 4, gi: 2; } eht; }; u8 rate_idx; u8 nss; u8 rx_flags; u8 band; u8 antenna; s8 signal; u8 chains;
	s8 chain_signal[IEEE80211_MAX_CHAINS]; u8 zero_length_psdu_type; u8 link_valid: 1, link_id: 4;
};
struct ieee80211_radiotap_he { __le16 data1, data2, data3, data4, data5, data6; };
struct ieee80211_radiotap_he_mu { __le16 flags1, flags2; u8 ru_ch1[4]; u8 ru_ch2[4]; };
struct rate_info { u16 flags; u16 legacy; u8 mcs; u8 nss; u8 bw; u8 he_gi; u8 he_dcm; u8 he_ru_alloc; u8 n_bonded_ch; u8 eht_gi; u8 eht_ru_alloc; };
#define RATE_INFO_FLAGS_MCS BIT(0)
#define RATE_INFO_FLAGS_VHT_MCS BIT(1)
#define RATE_INFO_FLAGS_SHORT_GI BIT(2)
#define RATE_INFO_FLAGS_HE_MCS BIT(4)
#define RATE_INFO_FLAGS_EHT_MCS BIT(7)

/* ---------------------------------------------------------------- channels / bands */
struct ieee80211_channel {
	enum nl80211_band band; u32 center_freq; u16 freq_offset; u16 hw_value; u32 flags;
	int max_antenna_gain; int max_power; int max_reg_power; bool beacon_found; u32 orig_flags;
	int orig_mag, orig_mpwr; enum nl80211_dfs_state dfs_state; unsigned long dfs_state_entered; unsigned int dfs_cac_ms;
};
#define IEEE80211_CHAN_DISABLED BIT(0)
#define IEEE80211_CHAN_NO_IR BIT(1)
#define IEEE80211_CHAN_RADAR BIT(3)
struct ieee80211_rate { u32 flags; u16 bitrate; u16 hw_value, hw_value_short; };
#define IEEE80211_RATE_SHORT_PREAMBLE BIT(0)
struct ieee80211_mcs_info { u8 rx_mask[10]; __le16 rx_highest; u8 tx_params; u8 reserved[3]; } __packed;
struct ieee80211_sta_ht_cap { u16 cap; bool ht_supported; u8 ampdu_factor; u8 ampdu_density; struct ieee80211_mcs_info mcs; };
struct ieee80211_vht_mcs_info { __le16 rx_mcs_map; __le16 rx_highest; __le16 tx_mcs_map; __le16 tx_highest; } __packed;
struct ieee80211_sta_vht_cap { bool vht_supported; u32 cap; struct ieee80211_vht_mcs_info vht_mcs; };
struct ieee80211_supported_band {
	struct ieee80211_channel *channels; struct ieee80211_rate *bitrates; enum nl80211_band band;
	int n_channels; int n_bitrates; struct ieee80211_sta_ht_cap ht_cap; struct ieee80211_sta_vht_cap vht_cap;
	void *iftype_data; u16 n_iftype_data;
};
struct cfg80211_chan_def {
	struct ieee80211_channel *chan; enum nl80211_chan_width width; u32 center_freq1; u32 center_freq2;
	u16 freq1_offset; u16 punctured;
};
struct cfg80211_sar_freq_ranges { u32 start_freq; u32 end_freq; };
struct cfg80211_sar_capa { int type; u32 num_freq_ranges; const struct cfg80211_sar_freq_ranges *freq_ranges; };
struct cfg80211_sar_sub_specs { s32 power; u32 freq_range_index; };
struct cfg80211_sar_specs { int type; u32 num_sub_specs; struct cfg80211_sar_sub_specs sub_specs[]; };
struct survey_info { struct ieee80211_channel *channel; u64 time; u64 time_busy; u64 time_ext_busy; u64 time_rx; u64 time_tx; u64 time_scan; u64 time_bss_rx; u32 filled; s8 noise; };
struct regulatory_request { enum nl80211_dfs_regions dfs_region; char alpha2[3]; };
static inline void cfg80211_chandef_create(struct cfg80211_chan_def *c, struct ieee80211_channel *ch, enum nl80211_channel_type t)
{ memset(c, 0, sizeof(*c)); c->chan = ch; c->width = t == NL80211_CHAN_NO_HT ? NL80211_CHAN_WIDTH_20_NOHT : NL80211_CHAN_WIDTH_20; c->center_freq1 = ch->center_freq; }
static inline int ieee80211_frequency_to_channel(int freq)
{ if (freq == 2484) return 14; if (freq < 2484) return (freq - 2407) / 5; if (freq >= 4910 && freq <= 4980) return (freq - 4000) / 5; return (freq - 5000) / 5; }
static inline int ieee80211_channel_to_frequency(int chan, enum nl80211_band band)
{ if (band == NL80211_BAND_2GHZ) return chan == 14 ? 2484 : 2407 + chan * 5; return 5000 + chan * 5; }
static inline u32 ieee80211_tu_to_usec(unsigned long tu) { return 1024 * tu; }

/* ---------------------------------------------------------------- hw / vif / sta / txq */
struct wiphy {
	u32 rts_threshold; struct device *dev_ptr; u8 perm_addr[ETH_ALEN]; u32 flags; u32 features; u16 interface_modes;
	struct ieee80211_supported_band *bands[NUM_NL80211_BANDS]; u32 available_antennas_tx, available_antennas_rx;
	const struct cfg80211_sar_capa *sar_capa; char fw_version[32]; u32 hw_version; int n_radio; u32 max_remain_on_channel_duration; const struct ieee80211_iface_combination *iface_combinations; int n_iface_combinations;
	void (*reg_notifier)(struct wiphy *, struct regulatory_request *); void *priv; char name[32];
	struct mac_address *addresses; u16 n_addresses; u8 max_scan_ssids; u16 max_scan_ie_len;
};
static inline const char *wiphy_name(const struct wiphy *w) { return w->name; }
static inline void *wiphy_priv(struct wiphy *w) { return w->priv; }
struct ieee80211_hw {
	struct ieee80211_conf { u32 flags; int power_level; struct cfg80211_chan_def chandef; bool radar_enabled; u16 listen_interval; u8 long_frame_max_tx_count, short_frame_max_tx_count; } conf;
	struct wiphy *wiphy; const char *rate_control_algorithm; void *priv; unsigned long flags[2];
	unsigned int extra_tx_headroom; unsigned int extra_beacon_tailroom; int vif_data_size; int sta_data_size;
	int chanctx_data_size; int txq_data_size; u16 queues; u16 max_listen_interval; s8 max_signal;
	u8 max_rates; u8 max_report_rates; u8 max_rate_tries; u16 max_rx_aggregation_subframes; u16 max_tx_aggregation_subframes;
	u8 max_tx_fragments; u8 offchannel_tx_hw_queue; u8 radiotap_mcs_details; u16 radiotap_vht_details;
	u8 uapsd_queues; u8 uapsd_max_sp_len; u8 max_nan_de_entries; u8 tx_sk_pacing_shift; u8 weight_multiplier;
	u32 max_mtu;
};
enum ieee80211_hw_flags { IEEE80211_HW_SUPPORTS_AMSDU_IN_AMPDU = 1, IEEE80211_HW_AMPDU_AGGREGATION, NUM_IEEE80211_HW_FLAGS = 128 };
#define ieee80211_hw_check(hw, flg) test_bit(IEEE80211_HW_##flg, (hw)->flags)
#define ieee80211_hw_set(hw, flg) set_bit(IEEE80211_HW_##flg, (hw)->flags)
#define SET_IEEE80211_DEV(hw, d) ((hw)->wiphy->dev_ptr = (d))
#define SET_IEEE80211_PERM_ADDR(hw, a) memcpy((hw)->wiphy->perm_addr, (a), ETH_ALEN)

enum ieee80211_smps_mode { IEEE80211_SMPS_AUTOMATIC, IEEE80211_SMPS_OFF, IEEE80211_SMPS_STATIC, IEEE80211_SMPS_DYNAMIC, IEEE80211_SMPS_NUM_MODES };
enum ieee80211_ac_numbers { IEEE80211_AC_VO = 0, IEEE80211_AC_VI = 1, IEEE80211_AC_BE = 2, IEEE80211_AC_BK = 3 };
enum ieee80211_sta_state { IEEE80211_STA_NOTEXIST, IEEE80211_STA_NONE, IEEE80211_STA_AUTH, IEEE80211_STA_ASSOC, IEEE80211_STA_AUTHORIZED };
enum ieee80211_frame_release_type { IEEE80211_FRAME_RELEASE_PSPOLL, IEEE80211_FRAME_RELEASE_UAPSD };
enum ieee80211_roc_type { IEEE80211_ROC_TYPE_NORMAL = 0, IEEE80211_ROC_TYPE_MGMT_TX };
enum ieee80211_reconfig_type { IEEE80211_RECONFIG_TYPE_RESTART, IEEE80211_RECONFIG_TYPE_SUSPEND };
enum ieee80211_chanctx_switch_mode { CHANCTX_SWMODE_REASSIGN_VIF, CHANCTX_SWMODE_SWAP_CONTEXTS };
enum ieee80211_ampdu_mlme_action { IEEE80211_AMPDU_RX_START, IEEE80211_AMPDU_RX_STOP, IEEE80211_AMPDU_TX_START,
	IEEE80211_AMPDU_TX_STOP_CONT, IEEE80211_AMPDU_TX_STOP_FLUSH, IEEE80211_AMPDU_TX_STOP_FLUSH_CONT, IEEE80211_AMPDU_TX_OPERATIONAL };
#define IEEE80211_HT_OP_MODE_PROTECTION 0x0003
#define IEEE80211_HT_OP_MODE_PROTECTION_NONE 0
#define IEEE80211_HT_OP_MODE_PROTECTION_NONMEMBER 1
#define IEEE80211_HT_OP_MODE_PROTECTION_20MHZ 2
#define IEEE80211_HT_OP_MODE_PROTECTION_NONHT_MIXED 3
#define IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT 0x0004

#include "kshim_80211ax.h"
struct ieee80211_bss_conf {
	u8 bssid_buf[ETH_ALEN]; const u8 *bssid; bool assoc; u16 aid; bool use_cts_prot; bool use_short_preamble;
	bool use_short_slot; u8 dtim_period; u16 beacon_int; u16 assoc_capability; u32 basic_rates; u16 ht_operation_mode;
	s32 cqm_rssi_thold; struct cfg80211_chan_def chanreq_chandef; int txpower; bool enable_beacon; bool csa_active; bool nontransmitted; u8 transmitter_bssid[ETH_ALEN]; struct { struct cfg80211_chan_def oper; } chanreq; u8 link_id;
	u8 addr[ETH_ALEN] __aligned(2); u8 bssid_indicator; bool color_change_active; u32 unsol_bcast_probe_resp_interval;
	bool qos; u32 cqm_rssi_hyst; int mcast_rate[NUM_NL80211_BANDS]; struct cfg80211_bitrate_mask beacon_tx_rate;
	u8 bssid_index; u16 frame_time_rts_th; bool he_support; bool htc_trig_based_pkt_ext; bool ht_ldpc; bool vht_ldpc;
	bool vht_su_beamformer, vht_su_beamformee, vht_mu_beamformer, vht_mu_beamformee;
	bool he_su_beamformer, he_su_beamformee, he_mu_beamformer; bool eht_su_beamformer, eht_su_beamformee, eht_mu_beamformer;
	struct ieee80211_fils_discovery fils_discovery; struct ieee80211_he_obss_pd he_obss_pd; struct cfg80211_he_bss_color he_bss_color;
	struct ieee80211_vif *vif;
};
struct ieee80211_vif_cfg { bool assoc; u16 aid; bool ps; };
struct ieee80211_vif {
	enum nl80211_iftype type; struct ieee80211_vif_cfg cfg; struct ieee80211_bss_conf bss_conf;
	struct ieee80211_bss_conf *link_conf[IEEE80211_MLD_MAX_NUM_LINKS];
	u16 valid_links, active_links; u8 addr[ETH_ALEN] __aligned(2); bool p2p; u8 cab_queue; u8 hw_queue[IEEE80211_NUM_ACS];
	struct ieee80211_txq *txq; u32 offload_flags; u32 driver_flags;
	u8 drv_priv[] __aligned(sizeof(void *));
};
static inline bool ieee80211_vif_is_mld(const struct ieee80211_vif *v) { return v->valid_links != 0; }
struct ieee80211_sta_ht_cap_dummy { int v; };
struct ieee80211_link_sta {
	struct ieee80211_sta *sta; u8 addr[ETH_ALEN]; u8 link_id; struct ieee80211_sta_ht_cap ht_cap;
	struct ieee80211_sta_vht_cap vht_cap; enum ieee80211_sta_rx_bandwidth_dummy_ignore { IEEE80211_STA_RX_BW_20 = 0, IEEE80211_STA_RX_BW_40, IEEE80211_STA_RX_BW_80, IEEE80211_STA_RX_BW_160, IEEE80211_STA_RX_BW_320 } bandwidth;
	u8 rx_nss; enum ieee80211_smps_mode smps_mode; u32 supp_rates[NUM_NL80211_BANDS];
	struct { u16 max_amsdu_len; } agg;
	struct ieee80211_sta_he_cap he_cap; struct ieee80211_he_6ghz_capa he_6ghz_capa; struct ieee80211_sta_eht_cap eht_cap;
};
struct ieee80211_sta {
	u8 addr[ETH_ALEN] __aligned(2); u16 aid; u16 max_rx_aggregation_subframes; bool wme; u8 uapsd_queues; u8 max_sp;
	struct ieee80211_link_sta deflink; struct ieee80211_link_sta *link[IEEE80211_MLD_MAX_NUM_LINKS];
	struct ieee80211_sta_rates __rcu *rates; u16 valid_links; bool mlo; bool tdls; bool mfp; u8 max_amsdu_subframes;
	struct ieee80211_txq *txq[IEEE80211_NUM_TIDS + 1];
	u8 drv_priv[] __aligned(sizeof(void *));
};
struct ieee80211_txq {
	struct ieee80211_vif *vif; struct ieee80211_sta *sta; u8 tid; u8 ac;
	u8 drv_priv[] __aligned(sizeof(void *));
};
struct ieee80211_key_conf {
	atomic64_t tx_pn; u32 cipher; u8 icv_len; u8 iv_len; u8 hw_key_idx; s8 keyidx; u16 flags; s8 link_id; u8 keylen; u8 key[];
};
#define IEEE80211_KEY_FLAG_GENERATE_IV BIT(1)
#define IEEE80211_KEY_FLAG_GENERATE_MMIC BIT(2)
#define IEEE80211_KEY_FLAG_PAIRWISE BIT(3)
#define IEEE80211_KEY_FLAG_SW_MGMT_TX BIT(4)
#define IEEE80211_KEY_FLAG_PUT_IV_SPACE BIT(5)
#define WLAN_CIPHER_SUITE_USE_GROUP 0x000FAC00
#define WLAN_CIPHER_SUITE_WEP40 0x000FAC01
#define WLAN_CIPHER_SUITE_TKIP 0x000FAC02
#define WLAN_CIPHER_SUITE_CCMP 0x000FAC04
#define WLAN_CIPHER_SUITE_WEP104 0x000FAC05
#define WLAN_CIPHER_SUITE_AES_CMAC 0x000FAC06
#define WLAN_CIPHER_SUITE_GCMP 0x000FAC08
#define WLAN_CIPHER_SUITE_GCMP_256 0x000FAC09
#define WLAN_CIPHER_SUITE_CCMP_256 0x000FAC0A
#define WLAN_CIPHER_SUITE_BIP_GMAC_128 0x000FAC0B
#define WLAN_CIPHER_SUITE_BIP_GMAC_256 0x000FAC0C
#define WLAN_CIPHER_SUITE_BIP_CMAC_256 0x000FAC0D
#define WLAN_CIPHER_SUITE_SMS4 0x00147201

/* ---------------------------------------------------------------- TX info / status */
struct ieee80211_tx_rate { s8 idx; u16 count: 5, flags: 11; } __packed;
enum mac80211_rate_control_flags {
	IEEE80211_TX_RC_USE_RTS_CTS = BIT(0), IEEE80211_TX_RC_USE_CTS_PROTECT = BIT(1),
	IEEE80211_TX_RC_USE_SHORT_PREAMBLE = BIT(2), IEEE80211_TX_RC_MCS = BIT(3), IEEE80211_TX_RC_GREEN_FIELD = BIT(4),
	IEEE80211_TX_RC_40_MHZ_WIDTH = BIT(5), IEEE80211_TX_RC_DUP_DATA = BIT(6), IEEE80211_TX_RC_SHORT_GI = BIT(7),
	IEEE80211_TX_RC_VHT_MCS = BIT(8), IEEE80211_TX_RC_80_MHZ_WIDTH = BIT(9), IEEE80211_TX_RC_160_MHZ_WIDTH = BIT(10),
};
static inline void ieee80211_rate_set_vht(struct ieee80211_tx_rate *r, u8 mcs, u8 nss) { r->idx = ((nss - 1) << 4) | mcs; }
static inline u8 ieee80211_rate_get_vht_mcs(const struct ieee80211_tx_rate *r) { return r->idx & 0xF; }
static inline u8 ieee80211_rate_get_vht_nss(const struct ieee80211_tx_rate *r) { return (r->idx >> 4) + 1; }
enum mac80211_tx_info_flags {
	IEEE80211_TX_CTL_REQ_TX_STATUS = BIT(0), IEEE80211_TX_CTL_ASSIGN_SEQ = BIT(1), IEEE80211_TX_CTL_NO_ACK = BIT(2),
	IEEE80211_TX_CTL_CLEAR_PS_FILT = BIT(3), IEEE80211_TX_CTL_FIRST_FRAGMENT = BIT(4), IEEE80211_TX_CTL_SEND_AFTER_DTIM = BIT(5),
	IEEE80211_TX_CTL_AMPDU = BIT(6), IEEE80211_TX_CTL_INJECTED = BIT(7), IEEE80211_TX_STAT_TX_FILTERED = BIT(8),
	IEEE80211_TX_STAT_ACK = BIT(9), IEEE80211_TX_STAT_AMPDU = BIT(10), IEEE80211_TX_STAT_AMPDU_NO_BACK = BIT(11),
	IEEE80211_TX_CTL_RATE_CTRL_PROBE = BIT(12), IEEE80211_TX_INTFL_OFFCHAN_TX_OK = BIT(13), IEEE80211_TX_CTL_HW_80211_ENCAP = BIT(14),
	IEEE80211_TX_INTFL_RETRIED = BIT(15), IEEE80211_TX_INTFL_DONT_ENCRYPT = BIT(16), IEEE80211_TX_CTL_NO_PS_BUFFER = BIT(17),
	IEEE80211_TX_CTL_MORE_FRAMES = BIT(18), IEEE80211_TX_INTFL_RETRANSMISSION = BIT(19), IEEE80211_TX_CTL_MLO_LINK = 0xf0000000,
	IEEE80211_TX_CTL_LDPC = BIT(22), IEEE80211_TX_CTL_STBC = BIT(23) | BIT(24), IEEE80211_TX_CTL_TX_OFFCHAN = BIT(25),
	IEEE80211_TX_INTFL_TKIP_MIC_FAILURE = BIT(26), IEEE80211_TX_CTL_NO_CCK_RATE = BIT(27), IEEE80211_TX_STATUS_EOSP = BIT(28),
	IEEE80211_TX_CTL_USE_MINRATE = BIT(29), IEEE80211_TX_CTL_DONTFRAG = BIT(30), IEEE80211_TX_STAT_NOACK_TRANSMITTED = BIT(31),
};
#define IEEE80211_TX_CTL_STBC_SHIFT 23
#define IEEE80211_TX_CTRL_PORT_CTRL_PROTO BIT(0)
#define IEEE80211_TX_CTRL_PS_RESPONSE BIT(1)
#define IEEE80211_TX_CTRL_RATE_INJECT BIT(2)
#define IEEE80211_TX_CTRL_AMSDU BIT(3)
#define IEEE80211_TX_CTRL_FAST_XMIT BIT(4)
#define IEEE80211_TX_CTRL_DONT_USE_RATE_MASK BIT(10)
struct ieee80211_tx_info {
	u32 flags; u32 band: 3, status_data_idr: 1, status_data: 13, hw_queue: 4, tx_time_est: 10;
	union {
		struct {
			union { struct { struct ieee80211_tx_rate rates[IEEE80211_TX_MAX_RATES]; s8 rts_cts_rate_idx; u8 use_rts: 1, use_cts_prot: 1, short_preamble: 1, skip_table: 1, antennas: 2; }; unsigned long jiffies; };
			struct ieee80211_vif *vif; struct ieee80211_key_conf *hw_key; u32 flags; u32 enqueue_time;
		} control;
		struct { u64 cookie; } ack;
		struct {
			struct ieee80211_tx_rate rates[IEEE80211_TX_MAX_RATES]; s32 ack_signal; u8 ampdu_ack_len; u8 ampdu_len; u8 antenna;
			u8 pad; u16 tx_time; u8 flags; u8 pad2; void *status_driver_data[16 / sizeof(void *)];
		} status;
		struct { struct ieee80211_tx_rate driver_rates[IEEE80211_TX_MAX_RATES]; u8 pad[4]; void *rate_driver_data[24 / sizeof(void *)]; };
		void *driver_data[40 / sizeof(void *)];
	};
};
static inline struct ieee80211_tx_info *IEEE80211_SKB_CB(struct sk_buff *skb) { return (struct ieee80211_tx_info *)skb->cb; }
static inline struct ieee80211_rx_status *IEEE80211_SKB_RXCB(struct sk_buff *skb) { return (struct ieee80211_rx_status *)skb->cb; }
static inline void ieee80211_tx_info_clear_status(struct ieee80211_tx_info *info)
{ int i; for (i = 0; i < IEEE80211_TX_MAX_RATES; i++) info->status.rates[i].count = 0; memset(&info->status.ampdu_ack_len, 0, sizeof(info->status) - offsetof(__typeof__(info->status), ampdu_ack_len)); }
struct ieee80211_rate_status { struct rate_info rate_idx; u8 try_count; u8 tx_power_idx; };
struct ieee80211_tx_status {
	struct ieee80211_sta *sta; struct ieee80211_tx_info *info; struct sk_buff *skb; struct ieee80211_rate_status *rates;
	ktime_t ack_hwtstamp; u8 n_rates; struct list_head *free_list;
};
struct ieee80211_tx_control { struct ieee80211_sta *sta; };
struct ieee80211_he_mu_edca_param_ac_rec;
struct ieee80211_tx_queue_params { u16 txop; u16 cw_min; u16 cw_max; u8 aifs; bool acm; bool uapsd; bool mu_edca;
	struct { u8 aifsn; u8 ecw_min_max; u8 mu_edca_timer; } __attribute__((packed)) mu_edca_param_rec; };
struct ieee80211_ampdu_params {
	enum ieee80211_ampdu_mlme_action action; struct ieee80211_sta *sta; u16 tid; u16 ssn; u16 buf_size; bool amsdu; u16 timeout;
};
struct ieee80211_chanctx_conf { struct cfg80211_chan_def def; struct cfg80211_chan_def min_def; u8 rx_chains_static, rx_chains_dynamic; bool radar_enabled; u8 drv_priv[] __aligned(sizeof(void *)); };
struct ieee80211_vif_chanctx_switch { struct ieee80211_vif *vif; struct ieee80211_bss_conf *link_conf; struct ieee80211_chanctx_conf *old_ctx; struct ieee80211_chanctx_conf *new_ctx; };
struct cfg80211_ssid { u8 ssid[IEEE80211_MAX_SSID_LEN]; u8 ssid_len; };
struct cfg80211_scan_request { struct cfg80211_ssid *ssids; int n_ssids; u32 n_channels; const u8 *ie; u16 duration; u32 flags; u8 mac_addr[ETH_ALEN]; u8 mac_addr_mask[ETH_ALEN]; u8 bssid[ETH_ALEN]; bool no_cck; struct ieee80211_channel *channels[]; };
struct sk_buff *ieee80211_probereq_get(struct ieee80211_hw *hw, const u8 *src_addr, const u8 *ssid, size_t ssid_len, size_t tailroom);
struct ieee80211_scan_ies { const u8 *ies[NUM_NL80211_BANDS]; size_t len[NUM_NL80211_BANDS]; const u8 *common_ies; size_t common_ie_len; };
struct ieee80211_scan_request { struct ieee80211_scan_ies ies; struct cfg80211_scan_request req; };
struct ieee80211_ops { int v; };
struct cfg80211_ops { int v; };

static inline void *ieee80211_queue_delayed_work(struct ieee80211_hw *hw, struct delayed_work *w, unsigned long d) { (void)hw; (void)w; (void)d; return NULL; }
#define ieee80211_queue_work(hw, w) ((void)(hw), (void)(w))
static inline struct ieee80211_sta *wcid_to_sta_dummy(void) { return NULL; }
static inline void ieee80211_sta_register_airtime(struct ieee80211_sta *pubsta, u8 tid, u32 tx_airtime, u32 rx_airtime)
{ (void)pubsta; (void)tid; (void)tx_airtime; (void)rx_airtime; }
static inline u32 ieee80211_calc_tx_airtime(struct ieee80211_hw *hw, struct ieee80211_tx_info *info, int len)
{ (void)hw; (void)info; return len; }
static inline void ieee80211_get_tx_rates(struct ieee80211_vif *vif, struct ieee80211_sta *sta, struct sk_buff *skb,
					  struct ieee80211_tx_rate *dest, int max_rates)
{ (void)vif; (void)sta; (void)skb; memset(dest, 0, sizeof(*dest) * max_rates); for (int i = 0; i < max_rates; i++) dest[i].idx = -1; }
static inline void ieee80211_tx_status_ext(struct ieee80211_hw *hw, struct ieee80211_tx_status *s) { (void)hw; (void)s; }
static inline struct ieee80211_txq *ieee80211_next_txq(struct ieee80211_hw *hw, u8 ac) { (void)hw; (void)ac; return NULL; }
static inline void ieee80211_txq_schedule_start(struct ieee80211_hw *hw, u8 ac) { (void)hw; (void)ac; }
static inline void ieee80211_txq_schedule_end(struct ieee80211_hw *hw, u8 ac) { (void)hw; (void)ac; }
static inline void ieee80211_return_txq(struct ieee80211_hw *hw, struct ieee80211_txq *txq, bool force) { (void)hw; (void)txq; (void)force; }
static inline struct sk_buff *ieee80211_tx_dequeue(struct ieee80211_hw *hw, struct ieee80211_txq *txq) { (void)hw; (void)txq; return NULL; }
static inline void ieee80211_tx_status_skb(struct ieee80211_hw *hw, struct sk_buff *skb) { (void)hw; kshim_free_skb(skb); }
static inline void ieee80211_free_txskb(struct ieee80211_hw *hw, struct sk_buff *skb) { (void)hw; kshim_free_skb(skb); }
static inline void ieee80211_stop_queues(struct ieee80211_hw *hw) { (void)hw; }
static inline void ieee80211_wake_queues(struct ieee80211_hw *hw) { (void)hw; }
static inline void ieee80211_stop_queue(struct ieee80211_hw *hw, int q) { (void)hw; (void)q; }
static inline void ieee80211_wake_queue(struct ieee80211_hw *hw, int q) { (void)hw; (void)q; }
static inline void ieee80211_sta_set_buffered(struct ieee80211_sta *sta, u8 tid, bool b) { (void)sta; (void)tid; (void)b; }
static inline void ieee80211_sta_ps_transition_ni(struct ieee80211_sta *sta, bool s) { (void)sta; (void)s; }
static inline void ieee80211_sta_uapsd_trigger(struct ieee80211_sta *sta, u8 tid) { (void)sta; (void)tid; }
static inline void ieee80211_sta_pspoll(struct ieee80211_sta *sta) { (void)sta; }


/* ---------------------------------------------------------------- config-path types (mt76x02_util.c) */
#define IEEE80211_HT_CAP_LDPC_CODING 0x0001
#define FIF_ALLMULTI BIT(1)
#define FIF_FCSFAIL BIT(2)
#define FIF_PLCPFAIL BIT(3)
#define FIF_BCN_PRBRESP_PROMISC BIT(4)
#define FIF_CONTROL BIT(5)
#define FIF_OTHER_BSS BIT(6)
#define FIF_PSPOLL BIT(7)
#define FIF_PROBE_REQ BIT(8)
enum set_key_cmd { SET_KEY, DISABLE_KEY };
#define IEEE80211_KEY_FLAG_RX_MGMT BIT(6)
#define IEEE80211_HW_SUPPORTS_HT_CCK_RATES 10
#define IEEE80211_HW_NEEDS_UNIQUE_STA_ADDR 11
#define IEEE80211_HW_HOST_BROADCAST_PS_BUFFERING 12
#define IEEE80211_AMPDU_TX_START_IMMEDIATE 1
enum ieee80211_bss_change {
	BSS_CHANGED_ASSOC = BIT(0), BSS_CHANGED_ERP_CTS_PROT = BIT(1), BSS_CHANGED_ERP_PREAMBLE = BIT(2),
	BSS_CHANGED_ERP_SLOT = BIT(3), BSS_CHANGED_HT = BIT(4), BSS_CHANGED_BASIC_RATES = BIT(5),
	BSS_CHANGED_BEACON_INT = BIT(6), BSS_CHANGED_BSSID = BIT(7), BSS_CHANGED_BEACON = BIT(8),
	BSS_CHANGED_BEACON_ENABLED = BIT(9),
};
struct ieee80211_iface_limit { u16 max; u16 types; };
struct ieee80211_iface_combination {
	const struct ieee80211_iface_limit *limits; u32 num_different_channels; u16 max_interfaces; u8 n_limits;
	bool beacon_int_infra_match; u8 radar_detect_widths; u8 radar_detect_regions; u32 beacon_int_min_gcd;
};
struct ieee80211_sta_rates { struct rcu_head rcu_head; struct { s8 idx; u8 count; u8 count_cts; u8 count_rts; u16 flags; } rate[IEEE80211_TX_RATE_TABLE_SIZE]; };
#define IEEE80211_SN_TO_SEQ(sn) (((sn) << 4) & IEEE80211_SCTL_SEQ)
#define IEEE80211_SEQ_TO_SN(seq) (((seq) & IEEE80211_SCTL_SEQ) >> 4)
#define wiphy_ext_feature_set(w, f) ((void)(w))
#define ieee80211_stop_tx_ba_cb_irqsafe(v, a, t) ((void)0)
#define ieee80211_start_tx_ba_cb_irqsafe(v, a, t) ((void)0)
#define ieee80211_send_bar(v, ra, tid, ssn) ((void)0)

#define IEEE80211_DEFAULT_AIRTIME_WEIGHT 256
#define IEEE80211_IFACE_ITER_NORMAL 0
#define IEEE80211_IFACE_ITER_RESUME_ALL BIT(0)
#define IEEE80211_IFACE_ITER_ACTIVE BIT(1)
#define IEEE80211_CONF_MONITOR BIT(0)
#define IEEE80211_CONF_PS BIT(1)
#define IEEE80211_CONF_IDLE BIT(2)
#define IEEE80211_CONF_OFFCHANNEL BIT(3)
#define IEEE80211_VIF_BEACON_FILTER BIT(0)
#define IEEE80211_VIF_SUPPORTS_CQM_RSSI BIT(1)
#define IEEE80211_HW_SUPPORTS_PS 13
#define IEEE80211_HW_SUPPORTS_DYNAMIC_PS 14
struct ieee80211_mutable_offsets { u16 tim_offset; u16 tim_length; u16 cntdwn_counter_offs[2]; u16 mbssid_off; };
static const unsigned char rfc1042_header[] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
static const unsigned char bridge_tunnel_header[] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };
#define ieee80211_iterate_active_interfaces_atomic(hw, flags, iter, data) ((void)(hw))
#define ieee80211_iterate_active_interfaces(hw, flags, iter, data) ((void)(hw))
#define ieee80211_iterate_interfaces(hw, flags, iter, data) ((void)(hw))
#define ieee80211_beacon_get_template(hw, vif, offs, link) ((struct sk_buff *)NULL)
#define ieee80211_ready_on_channel(hw) ((void)(hw))
#define ieee80211_remain_on_channel_expired(hw) ((void)(hw))
#define ieee80211_radar_detected(hw, ctx) ((void)(hw))
#define ieee80211_csa_finish(vif, link) ((void)(vif))
#define ieee80211_beacon_cntdwn_is_complete(vif, link) false
#define cfg80211_reg_can_beacon(w, c, t) true
#define ieee80211_tx_status_noskb(hw, sta, info) ((void)(hw))
#define ieee80211_restart_hw(hw) ((void)(hw))
#define ieee80211_scan_completed(hw, info) ((void)(hw))

/* ---------------------------------------------------------------- core (mac80211.c) */
#define IEEE80211_TX_CTRL_MLO_LINK 0xf0000000
#define IEEE80211_LINK_UNSPECIFIED 0xf
#define WIPHY_FLAG_IBSS_RSN BIT(3)
#define WIPHY_FLAG_SUPPORTS_TDLS BIT(4)
#define WIPHY_FLAG_HAS_CHANNEL_SWITCH BIT(5)
#define WIPHY_FLAG_AP_UAPSD BIT(6)
#define SURVEY_INFO_NOISE_DBM BIT(0)
#define SURVEY_INFO_IN_USE BIT(1)
#define SURVEY_INFO_TIME BIT(2)
#define SURVEY_INFO_TIME_BUSY BIT(3)
#define SURVEY_INFO_TIME_BSS_RX BIT(7)
#define IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL 0
#define IEEE80211_HT_CAP_SUP_WIDTH_20_40 0x0002
#define IEEE80211_HT_CAP_GRN_FLD 0x0010
#define IEEE80211_HT_CAP_SGI_20 0x0020
#define IEEE80211_HT_CAP_SGI_40 0x0040
#define IEEE80211_HT_CAP_TX_STBC 0x0080
#define IEEE80211_HT_CAP_RX_STBC_SHIFT 8
#define IEEE80211_HT_MCS_TX_DEFINED 0x01
#define IEEE80211_HT_MCS_MASK_LEN 10
#define IEEE80211_HT_MAX_AMPDU_64K 3
#define IEEE80211_VHT_MCS_SUPPORT_0_9 2
#define IEEE80211_VHT_MCS_NOT_SUPPORTED 3
#define IEEE80211_VHT_EXT_NSS_BW_CAPABLE BIT(13)
#define IEEE80211_VHT_CAP_RXLDPC 0x00000010
#define IEEE80211_VHT_CAP_SHORT_GI_80 0x00000020
#define IEEE80211_VHT_CAP_TXSTBC 0x00000080
#define IEEE80211_VHT_CAP_RXSTBC_1 0x00000100
#define IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT 23
#define IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN 0x10000000
#define IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN 0x20000000
#define IEEE80211_TPT_LEDTRIG_FL_RADIO BIT(0)
enum {
	IEEE80211_HW_TX_FRAG_LIST = 20, IEEE80211_HW_TX_AMSDU, IEEE80211_HW_SUPPORTS_VHT_EXT_NSS_BW,
	IEEE80211_HW_SUPPORTS_REORDERING_BUFFER, IEEE80211_HW_SUPPORTS_RC_TABLE, IEEE80211_HW_SUPPORTS_CLONED_SKBS,
	IEEE80211_HW_SUPPORT_FAST_XMIT, IEEE80211_HW_SPECTRUM_MGMT, IEEE80211_HW_SIGNAL_DBM,
	IEEE80211_HW_REPORTS_TX_ACK_STATUS, IEEE80211_HW_MFP_CAPABLE, IEEE80211_HW_AP_LINK_PS,
};
struct ieee80211_tpt_blink { int throughput; int blink_time; };
struct ieee80211_key_seq { union { struct { u32 iv32; u16 iv16; } tkip; struct { u8 pn[6]; } ccmp; struct { u8 pn[6]; } aes_cmac;
	struct { u8 pn[6]; } aes_gmac; struct { u8 pn[6]; } gcmp; struct { u8 seq[16]; u8 seq_len; } hw; }; };
static inline void ieee80211_get_key_rx_seq(struct ieee80211_key_conf *k, int tid, struct ieee80211_key_seq *seq)
{ (void)k; (void)tid; memset(seq, 0, sizeof(*seq)); }
#define wiphy_read_of_freq_limits(w) ((void)(w))
#define ieee80211_register_hw(hw) 0
#define ieee80211_unregister_hw(hw) ((void)(hw))
#define ieee80211_free_hw(hw) ((void)(hw))
void kshim_ieee80211_alloc_hw_unused(void);
struct ieee80211_hw *kshim_ieee80211_alloc_hw(size_t priv, const struct ieee80211_ops *ops);
#define ieee80211_alloc_hw(p, o) kshim_ieee80211_alloc_hw(p, o)
#define ieee80211_alloc_hw_nm(p, o, n) kshim_ieee80211_alloc_hw(p, o)
#define ieee80211_vif_usable_links(v) ((u16)0)
#define ieee80211_tx_prepare_skb(hw, vif, skb, band, sta) false
#define ieee80211_sta_ps_transition(sta, ps) 0
/* mac80211's RX entry: the end of the driver's receive path; the shim consumes the frame */
static inline void ieee80211_rx_list(struct ieee80211_hw *hw, struct ieee80211_sta *sta, struct sk_buff *skb, struct list_head *list)
{ (void)hw; (void)sta; (void)list; kshim_free_skb(skb); }
static inline void ieee80211_rx_napi(struct ieee80211_hw *hw, struct ieee80211_sta *sta, struct sk_buff *skb, struct napi_struct *napi)
{ (void)hw; (void)sta; (void)napi; kshim_free_skb(skb); }
#define netif_receive_skb_list(l) ((void)(l))
#define napi_gro_receive(n, skb) kshim_free_skb(skb)
#define ieee80211_nullfunc_get(hw, vif, link, qos) ((struct sk_buff *)NULL)
#define ieee80211_find_sta_by_ifaddr(hw, a, l) ((struct ieee80211_sta *)NULL)
#define ieee80211_find_sta(vif, a) ((struct ieee80211_sta *)NULL)
#define ieee80211_create_tpt_led_trigger(hw, f, b, n) ((const char *)NULL)
#define ieee80211_calc_rx_airtime(hw, status, len) ((u32)(len))
#define ieee80211_beacon_loss(vif) ((void)(vif))

/* ---------------------------------------------------------------- tx.c */
#ifndef NL80211_IFTYPE_NAN_DATA
#define NL80211_IFTYPE_NAN_DATA (NUM_NL80211_IFTYPES + 1)
#endif
#define IEEE80211_QOS_CTL_TAG1D_MASK 0x0007
#define IEEE80211_STYPE_PROBE_REQ 0x0040
#define IEEE80211_STYPE_DEAUTH 0x00C0
static inline bool ieee80211_is_probe_req(__le16 fc) { return _FC_IS(fc, IEEE80211_FTYPE_MGMT, IEEE80211_STYPE_PROBE_REQ); }
static inline bool ieee80211_is_deauth(__le16 fc) { return _FC_IS(fc, IEEE80211_FTYPE_MGMT, IEEE80211_STYPE_DEAUTH); }
#define ieee80211_schedule_txq(hw, txq) ((void)(hw))
#define ieee80211_txq_get_depth(txq, f, b) (*(f) = 0, *(b) = 0)
#define ieee80211_txq_aql_pending(hw, txq) false
#define ieee80211_sta_eosp(sta) ((void)(sta))
static inline void ieee80211_purge_tx_queue(struct ieee80211_hw *hw, struct sk_buff_head *l) { (void)hw; __skb_queue_purge(l); }

#endif
