#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <stddef.h>

#include "bpf_helpers.h"

#define trace_printk(fmt, ...) do { \
	char _fmt[] = fmt; \
	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
	} while (0)

/* compiler workaround */
#define bpf_htonl __builtin_bswap32
#define bpf_memcpy __builtin_memcpy

#define ICMP_PING 8

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

SEC("classifier")
int cls_main(struct __sk_buff *skb)
{
	return -1;
}

SEC("action")
int pingpong(struct __sk_buff *skb)
{
	/* We will access all data through pointers to structs */
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end)
		return TC_ACT_UNSPEC;

	/* for easy access we re-use the Kernel's struct definitions */
	struct ethhdr  *eth  = data;
	struct iphdr   *ip   = (data + sizeof(struct ethhdr));

	/* Only actual IP packets are allowed */
	if (eth->h_proto != __constant_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	/* Let's grab the MAC address.
	 * We need to copy them out, as they are 48 bits long */
	 // MAC of enp2s0 (2)
	__u8 src_mac[] = {120, 50, 27, 113, 129, 184};
	// MAC of machine-a
	__u8 dst_mac[] = {164, 93, 54, 109, 62, 186};

	/* Let's grab the IP addresses.
	 * They are 32-bit, so it is easy to access */
	__u32 src_ip = ip->saddr;
	__u32 dst_ip = ip->daddr;

	trace_printk("src= %lu, dst= %lu\n", src_ip, dst_ip);
	// trace_printk("%d\n",skb->ifindex);

	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), src_mac, ETH_ALEN, 0);
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, ETH_ALEN, 0);

	/* Now redirecting the modified skb on the same interface to be transmitted again */
	// bpf_clone_redirect(skb, skb->ifindex, 0);
	// 2: enp2s0
	// 3: enp2s1
	// bpf_redirect(2, 0);
	bpf_clone_redirect(skb, 2, 0);
	// send on enp2s0 egress

	/* We modified the packet and redirected it, it can be dropped here */
	return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";
