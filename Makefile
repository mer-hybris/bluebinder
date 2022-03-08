# TODO: this is a bit minimalistic isn't it?

CC ?= $(CROSS_COMPILE)gcc
USE_SYSTEMD ?= 1

DEPEND_LIBS = libgbinder glib-2.0
ifeq ($(USE_SYSTEMD),1)
DEPEND_LIBS += libsystemd
endif

build: bluebinder

bluebinder: bluebinder.c
	$(CC) $(CFLAGS) -Wall -flto $^ `pkg-config --cflags --libs $(DEPEND_LIBS)` -DUSE_SYSTEMD=$(USE_SYSTEMD) -o $@

install:
	mkdir -p $(DESTDIR)/usr/sbin
	cp bluebinder $(DESTDIR)/usr/sbin

clean:
	rm bluebinder

