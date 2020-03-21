obj-m += fentanull.o
CC = gcc -Wall
modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
modules_install: 
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules_install
.PHONY: modules modules_install  
