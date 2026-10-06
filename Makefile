ifneq ($(KERNELRELEASE),)
obj-m := kvm_uintr.o
kvm_uintr-y := main.o hook.o uintr.o
else
KDIR ?= /lib/modules/$(shell uname -r)/build
.PHONY: all clean
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
endif
