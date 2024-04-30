/*#########################################################################
# File Name: toy-proxy-bpf-sock.c
# Author:
# Email:
# Created Time: Tue 30 Apr 2024 09:12:02 AM CST
#########################################################################*/

#include <linux/bpf.h>

#ifndef __section
#define __section(NAME) \
	__attribute__((section(NAME), used))
#endif

static int
__sock4_xlate_fwd(struct bpf_sock_addr *ctx) {
	const __be32 cluster_ip = 0x846F070A; // 10.7.111.132
	const __be32 pod_ip = 0x0529050A;     // 10.5.41.5

	if (ctx->user_ip4 != cluster_ip) {
		return 0;
	}

	ctx->user_ip4 = pod_ip;
	return 0;
}

__section("connect4")
int sock4_connect(struct bpf_sock_addr *ctx) {
	__sock4_xlate_fwd(ctx);
	return SYS_PROCEED;
}
