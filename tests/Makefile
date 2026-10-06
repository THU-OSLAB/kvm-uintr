CC ?= gcc
LD ?= ld
OBJCOPY ?= objcopy
CASES := msr-smoke self-uipi cross-uipi
.PHONY: all clean
all: $(addprefix build/kvm-,$(CASES)) build/msr-guest.bin build/self-uipi-guest.bin build/cross-uipi-guest.bin
build:
	mkdir -p $@
build/kvm-%: kvm-%.c | build
	$(CC) -O2 -Wall -Wextra -pthread $< -o $@
build/%.o: %.S ../registers.h | build
	$(CC) -c -nostdlib -o $@ $<
build/%.elf: build/%.o
	$(LD) -nostdlib -Ttext=0x10000 -e _start -o $@ $<
build/%.bin: build/%.elf
	$(OBJCOPY) -O binary $< $@
clean:
	rm -rf build
