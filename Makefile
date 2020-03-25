obj-m += fentanull.o
CC = gcc -Wall
ldflags-y += -T$(src)/khook/engine.lds
modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
modules_install: 
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules_install
clean: 
	rm Module.symvers; rm fentanull.mod.*; rm modules.order; rm fentanull.o
.PHONY: modules modules_install clean
