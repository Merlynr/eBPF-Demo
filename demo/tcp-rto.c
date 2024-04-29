/*#########################################################################
# File Name: tcp-rto.c
# Author:
# Email:
# Created Time: Mon 29 Apr 2024 10:49:13 AM CST
#########################################################################*/

#include <linux/bpf.h>

#ifndef __section
#define __section(NAME)	\
	__attribute__((section(NAME), used))
#endif

__section("sockops")

int set_initial_rto(struct bpf_sock_ops *skops)
{
	int timeout = 3;
	int hz = 250;

	int op = (int) skops->op;
	if(op == BPF_SOCK_OPS_TIME_INIT){
		skops->reply = hz * timeout;
	}

	return 1;
}

char _license[] __section("license") = "GPL";
