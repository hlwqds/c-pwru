# c-pwru Makefile

CLANG ?= clang
CC ?= gcc
CFLAGS := -g -O2 -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# Directories
SRC_DIR := src
BUILD_DIR := build
LIBBPF_DIR := libbpf/src
LIBBPF_OBJ := $(LIBBPF_DIR)/libbpf.a
LIBBPF_HEADERS := $(BUILD_DIR)/libbpf_headers

# In-tree libbpf includes
INCLUDES := -I$(LIBBPF_HEADERS)/usr/include -I$(SRC_DIR)

# Dependencies
LIBS := $(LIBBPF_OBJ) -lelf -lz

BPF_SRC := $(SRC_DIR)/pwru.bpf.c
BPF_OBJ := $(BUILD_DIR)/pwru.bpf.o

USER_SRC := $(SRC_DIR)/pwru.c \
            $(SRC_DIR)/pwru_kprobe.c \
            $(SRC_DIR)/pwru_fentry.c \
            $(SRC_DIR)/pwru_kprobe_multi.c \
            $(SRC_DIR)/pwru_error.c \
            $(SRC_DIR)/pwru_cli.c
USER_BIN := $(BUILD_DIR)/pwru

.PHONY: all clean clean-all libbpf_headers

all: $(USER_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build libbpf locally
$(LIBBPF_OBJ):
	@echo "  BUILD    libbpf"
	@$(MAKE) -C $(LIBBPF_DIR) > /dev/null

# Install libbpf headers to build dir
$(LIBBPF_HEADERS):
	@echo "  INSTALL  libbpf headers"
	@$(MAKE) -C $(LIBBPF_DIR) install_headers DESTDIR=$(abspath $(LIBBPF_HEADERS)) > /dev/null

# Compile eBPF program
$(BPF_OBJ): $(BPF_SRC) | $(BUILD_DIR) $(LIBBPF_HEADERS)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I$(LIBBPF_HEADERS)/usr/include \
		-I$(SRC_DIR) \
		-c $(BPF_SRC) -o $(BPF_OBJ)

# Compile User-space program
$(USER_BIN): $(USER_SRC) $(BPF_OBJ) $(LIBBPF_OBJ) | $(BUILD_DIR) $(LIBBPF_HEADERS)
	$(CC) $(CFLAGS) $(USER_SRC) $(INCLUDES) -o $(USER_BIN) $(LIBS)

clean:
	rm -rf $(BUILD_DIR)

clean-all: clean
	$(MAKE) -C $(LIBBPF_DIR) clean