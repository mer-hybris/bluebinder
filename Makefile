# TODO: this is a bit minimalistic isn't it?

DESTDIR ?= /

build:
	gcc -Wall -O3 -flto bluebinder.c `pkg-config --cflags libgbinder` `pkg-config --libs libgbinder` -lsystemd -o bluebinder

install:
	mkdir -p $(DESTDIR)/usr/sbin
	cp bluebinder $(DESTDIR)/usr/sbin

clean:
	rm bluebinder

