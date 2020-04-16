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

all:	$(LIBS) $(PROGRAMS)


%:	%.c $(LIBS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) 
clean:
	rm -f $(PROGRAMS) dnsdict6 thcping6 dnssecwalk $(LIBS) core DEADJOE *~

backup:	clean
	tar czvf ../thc-ipv6-bak.tar.gz *
	sync

.PHONY: all install clean 
