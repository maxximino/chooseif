KERNELDIR=/lib/modules/$(shell uname -r)/build/
obj-m += xt_CHOOSEIF.o
XTABLES_DIR=$(shell pkg-config --variable=xtlibdir xtables)
MAN_DIR=/usr/share/man
SBIN_DIR=/usr/sbin
all: libxt_CHOOSEIF.so chooseif_lowlevel
	make -C $(KERNELDIR) M=$(PWD) modules

install: all
	make -C $(KERNELDIR) M=$(PWD) modules_install
	cp libxt_CHOOSEIF.so $(XTABLES_DIR)/
	cp chooseif.sh $(SBIN_DIR)/chooseif
	chmod 700 $(SBIN_DIR)/chooseif
	cp chooseif_lowlevel $(SBIN_DIR)/chooseif_lowlevel
	chmod 700 $(SBIN_DIR)/chooseif_lowlevel
	cp chooseif.8 $(MAN_DIR)/man8/
	cp chooseif_lowlevel.8 $(MAN_DIR)/man8/
clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	-test -z libxt_CHOOSEIF.so || rm -f libxt_CHOOSEIF.so
	-test -z chooseif_lowlevel || rm -f chooseif_lowlevel
libxt_CHOOSEIF.so: libxt_CHOOSEIF.c
	gcc -fPIC -shared -o $@ $^ 

chooseif_lowlevel: chooseif_lowlevel.c
	gcc -o $@ $^ -lcap
	
