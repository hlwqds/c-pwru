# c-pwru Makefile

CLANG ?= clang
CFLAGS := -g -O2 -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# Libbpf dependencies (assuming installed in system)
LIBS := -lbpf -lelf -lz

SRC_DIR := src
BUILD_DIR := build

BPF_SRC := $(SRC_DIR)/pwru.bpf.c
BPF_OBJ := $(BUILD_DIR)/pwru.bpf.o

USER_SRC := $(SRC_DIR)/pwru.c
USER_BIN := $(BUILD_DIR)/pwru

.PHONY: all clean

all: $(USER_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile eBPF program
$(BPF_OBJ): $(BPF_SRC) | $(BUILD_DIR)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/x86_64-linux-gnu -I$(SRC_DIR) -c $(BPF_SRC) -o $(BPF_OBJ)

# Compile User-space program
$(USER_BIN): $(USER_SRC) $(BPF_OBJ) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(USER_SRC) -o $(USER_BIN) $(LIBS)

clean:
	rm -rf $(BUILD_DIR)
