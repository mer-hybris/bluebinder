# TODO: this is a bit minimalistic isn't it?

CC ?= $(CROSS_COMPILE)gcc
USE_SYSTEMD ?= 1

DEPEND_LIBS = libgbinder glib-2.0
ifeq ($(USE_SYSTEMD),1)
DEPEND_LIBS += libsystemd
endif

build: bluebinder

bluebinder: bluebinder.c mtu_quirk.c mtu_quirk.h
	$(CC) $(CFLAGS) -Wall -flto bluebinder.c mtu_quirk.c `pkg-config --cflags --libs $(DEPEND_LIBS)` -DUSE_SYSTEMD=$(USE_SYSTEMD) -o $@

install:
	mkdir -p $(DESTDIR)/usr/sbin
	cp bluebinder $(DESTDIR)/usr/sbin

clean:
	rm bluebinder


.PHONY: check
check:
	$(CC) $(CFLAGS) -Wall -Wextra -Werror -I. mtu_quirk.c tests/test_mtu_quirk.c -o test-mtu-quirk
	./test-mtu-quirk
	rm -f test-mtu-quirk
