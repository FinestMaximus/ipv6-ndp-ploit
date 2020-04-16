#
# Comment out if openssl-dev is not available
HAVE_SSL=yes

CC=gcc
#CFLAGS=-g
CFLAGS=-O2
CFLAGS+=$(if $(HAVE_SSL),-D_HAVE_SSL,)
LDFLAGS+=-lpcap $(if $(HAVE_SSL),-lssl -lcrypto,)
PROGRAMS= prog1 prog2
LIBS=thc-ipv6-lib.o
STRIP=echo

PREFIX=/usr/local
MANPREFIX=${PREFIX}/share/man

all:	$(LIBS) $(PROGRAMS) dnssecwalk dnsdict6 thcping6

dnssecwalk:	dnssecwalk.c
	$(CC) $(CFLAGS) -o $@ $^

dnsdict6:	dnsdict6.c
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lresolv

thcping6:	thcping6.c $(LIBS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lrt

%:	%.c $(LIBS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) 

strip:	all
	$(STRIP) $(PROGRAMS) dnssecwalk dnsdict6 thcping6

install: all strip
	install -m0755 -d ${DESTDIR}${PREFIX}/bin
	install -m0755 $(PROGRAMS) dnsdict6 thcping6 dnssecwalk *.sh ${DESTDIR}${PREFIX}/bin
	install -m0755 -d ${DESTDIR}${MANPREFIX}/man8
	install -m0644 -D thc-ipv6.8 ${DESTDIR}${MANPREFIX}/man8

clean:
	rm -f $(PROGRAMS) dnsdict6 thcping6 dnssecwalk $(LIBS) core DEADJOE *~

backup:	clean
	tar czvf ../thc-ipv6-bak.tar.gz *
	sync

.PHONY: all install clean 
