# BPF Makefile
# Compiles xdp_prog.c → xdp_prog.o using clang/LLVM BPF backend

CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool

ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -O2 -g -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -Wall -Werror \
              -I./headers

SRC  := xdp_prog.c
OBJ  := xdp_prog.o

.PHONY: all clean vmlinux

all: vmlinux $(OBJ)

# Generate vmlinux.h from the running kernel's BTF info
vmlinux:
	@if [ ! -f headers/vmlinux.h ]; then \
		echo "Generating vmlinux.h from kernel BTF..."; \
		mkdir -p headers; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h; \
	fi

$(OBJ): $(SRC) xdp_prog.h
	$(CLANG) $(BPF_CFLAGS) -c $(SRC) -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f $(OBJ)
	rm -f headers/vmlinux.h
