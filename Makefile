obj-m += KBlocker.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules
	gcc KBlockerUM.c -lcrypto -o KBlockerUM

clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean
	rm KBlockerUM