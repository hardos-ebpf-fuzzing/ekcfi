KERNEL_SRC := $(abspath ../linux)
SUBDIR= $(PWD)

obj-m := ekcfi.o
ekcfi-y := ekcfi_main.o ekcfi_tramp_$(BITS).o

.PHONY: clean

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(SUBDIR) modules

clean:
	$(RM) *~ *.ko *.o *.mod *.mod.c .*.cmd Module.symvers modules.order