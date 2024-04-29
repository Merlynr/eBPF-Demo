# https://arthurchiao.art/blog/customize-tcp-initial-rto-with-bpf/
# fix prog id
PROG_ID:=69


all: Hello
Hello:
	clang -O2 -target bpf -c tcp-rto.c -o tcp-rto.o
	sudo bpftool prog load tcp-rto.o /sys/fs/bpf/tcp-rto
	sudo bpftool prog show
	sudo bpftool cgroup attach /sys/fs/cgroup/ sock_ops id $(PROG_ID)
clean:
	sudo rm /sys/fs/bpf/tcp-rto
	sudo bpftool cgroup detach /sys/fs/cgroup/ sock_ops id $(PROG_ID)

