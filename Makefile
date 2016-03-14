CC=cc
PACKAGE=mqtt-sn-tools
VERSION=0.0.3
CFLAGS=-g -Wall -DVERSION=$(VERSION)
LDFLAGS=
TARGETS=mqtt-sn-pub mqtt-sn-sub mqtt-sn-serial-bridge mqtt-sn-pubs mqtt-sn-subs


all: clean $(TARGETS)

$(TARGETS): %: mqtt-sn.o presentcbc.o %.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o : %.c mqtt-sn.h presentcbc.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o $(TARGETS)

dist:
	distdir='$(PACKAGE)-$(VERSION)'; mkdir $$distdir || exit 1; \
	list=`git ls-files`; for file in $$list; do \
		cp -pR $$file $$distdir || exit 1; \
	done; \
	tar -zcf $$distdir.tar.gz $$distdir; \
	rm -fr $$distdir

pubs:
	gcc mqtt-sn-pubs.c mqtt-sn.c presentcbc.c -o mqtt-sn-pubs aes/aes.c -Os

subs:

	gcc mqtt-sn-subs.c mqtt-sn.c presentcbc.c -o mqtt-sn-subs

.PHONY: all clean dist
