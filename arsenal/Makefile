# Arsenal — VoidLink-style plugin specimens
# Compiles C plugins as ELF relocatable objects (.o / ET_REL)
# These are NOT shared libraries — they mirror VoidLink's BOF-style loading

CC := gcc
CFLAGS := -c -fPIC -fno-stack-protector -nostdlib -ffreestanding \
          -Wall -Wextra -O2 \
          -I include
BUILD_DIR ?= ../build/arsenal

# Operational mode: make arsenal OPERATIONAL=1
OPERATIONAL ?= 0
ifeq ($(OPERATIONAL),1)
CFLAGS += -DOPERATIONAL
endif

# Plugin sources
PLUGINS := recon cred_harvest persist

# Plugin objects
PLUGIN_OBJS := $(addprefix $(BUILD_DIR)/,$(addsuffix .o,$(PLUGINS)))

.PHONY: all clean

all: $(PLUGIN_OBJS)
	@echo "[+] Built $(words $(PLUGIN_OBJS)) arsenal plugins$(if $(filter 1,$(OPERATIONAL)), (OPERATIONAL),)"

$(BUILD_DIR)/%.o: %.c include/plugin_api.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<
	@echo "  [+] $< → $@"

clean:
	rm -f $(BUILD_DIR)/*.o
