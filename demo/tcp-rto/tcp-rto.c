/*#########################################################################
# File Name: tcp-rto.c
# Author:
# Email:
# Created Time: Mon 29 Apr 2024 10:49:13 AM CST
#########################################################################*/

#include <linux/bpf.h>

#ifndef __section
#define __section(NAME) \
	__attribute__((section(NAME), used))
#endif

#ifndef BPF_FUNC
#define BPF_FUNC(NAME, ...) \
	(*NAME)(__VA_ARGS__) = (void *)
#endif

static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

#ifndef printk
#define printk(fmt, ...)                                                       \
	({                                                                           \
	 char ____fmt[] = fmt;                                                        \
	 trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                         \
	 })
#endif

__section("sockops")
int set_initial_rto(struct bpf_sock_ops *skops) {
	const int timeout = 3;
	const int hz = 250; // grep 'CONFIG_HZ=' /boot/config-$(uname -r), HZ of my machine

	int op = (int)skops->op;
	if (op == BPF_SOCK_OPS_TIMEOUT_INIT) {
		skops->reply = hz * timeout; // 3s
		printk("SET TCP connect timeout = %ds\n", timeout);
		return 1;
	}

	printk("Miss, op=%d\n", op);
	return 1;
}

char _license[] __section("license") = "GPL";
