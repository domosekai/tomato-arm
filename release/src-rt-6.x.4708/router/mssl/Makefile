include ../common.mak

CFLAGS	= -Os -Wall $(EXTRACFLAGS) -fPIC -Wsign-compare
LIBS =
LDFLAGS	=

ifeq ($(TCONFIG_OPENSSL11),y)
CFLAGS	+= -I$(TOP)/openssl-1.1/include -DUSE_OPENSSL
LIBS += -L$(TOP)/openssl-1.1 -lssl -lcrypto
else
CFLAGS	+= -I$(TOP)/openssl/include -DUSE_OPENSSL
LIBS += -L$(TOP)/openssl -lssl -lcrypto
endif

ifneq ($(TCONFIG_BCMARM),y)
LIBS += -lpthread
endif
OBJ = mssl.o

all: libmssl.so libmssl.a

libmssl.so: $(OBJ)
ifeq ($(TCONFIG_BCMARM),y)
	$(LD) $(LIBS) -shared -o $@ $^
else
	$(CC) -shared -o $@ $^ $(LIBS)
endif
	$(STRIP) $@
	$(CPTMP)

libmssl.a: $(OBJ)
	rm -f $@
	$(AR) cruv $@ $^

clean:
	rm -f .*.depend *.o *.so *.a

install: all
	@echo " [mssl] Installing..."
	install -D libmssl.so $(INSTALLDIR)/usr/lib/libmssl.so
ifneq ($(TCONFIG_BCMARM),y)
	$(STRIP) $(INSTALLDIR)/usr/lib/libmssl.so
endif

%.o: %.c .%.depend
	@echo " [mssl] CC $@"
	@$(CC) $(CFLAGS) -c $<

.depend: $(OBJS:%.o=%.c)
	@$(CC) $(CFLAGS) -M $^ > .depend

.%.depend: %.c
	@$(CC) $(CFLAGS) -M $< > $@

-include $(OBJS:%.o=.%.depend)
