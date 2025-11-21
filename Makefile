# Makefile (root directory)

BPF_CLANG ?= clang
CC ?= clang

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "")
LIBBPF_LDLIBS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

CFLAGS := -O2 -g -Wall -Iinclude
LDFLAGS :=

# Warning if pkg-config fails
ifeq ($(LIBBPF_LDLIBS),-lbpf -lelf -lz)
$(warning pkg-config for libbpf failed, using fallback: -lbpf -lelf -lz)
endif

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86

BPF_OBJ := bpf/aid_lsm.bpf.o
USER_BIN := src/aid_lsm_loader src/addagent

all: $(BPF_OBJ) $(USER_BIN)

# Build BPF object
bpf/aid_lsm.bpf.o: bpf/aid_lsm.bpf.c bpf/vmlinux.h include/aid_shared.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# Userland binaries
src/aid_lsm_loader: src/aid_lsm_loader.c include/aid_shared.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LDLIBS)

src/addagent: src/addagent.c include/aid_shared.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LDLIBS)

clean:
	rm -f $(BPF_OBJ) $(USER_BIN)
