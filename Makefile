# TODO: this is a bit minimalistic isn't it?

build: bluebinder

bluebinder: bluebinder.c
	gcc $(CFLAGS) -Wall -flto $^ `pkg-config --cflags --libs libgbinder glib-2.0 libsystemd` -o $@

install:
	mkdir -p $(DESTDIR)/usr/sbin
	cp bluebinder $(DESTDIR)/usr/sbin

clean:
	rm bluebinder

