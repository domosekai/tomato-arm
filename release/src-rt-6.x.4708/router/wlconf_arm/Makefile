#
# Router Wireless Interface Configuration Utility Makefile
#
# Copyright (C) 2013, Broadcom Corporation
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#
# $Id: Makefile 401201 2013-05-09 03:06:42Z $
#
include ../common.mak

CFLAGS	+= -I. -I$(TOP)/shared -I$(SRCBASE)/include -I$(SRCBASE)/common/include -Wall
CFLAGS	+= $(WLAN_ComponentIncPath)
#CFLAGS	+= -g -DDEBUG
CFLAGS	+= -s
ifeq ($(CONFIG_TR_OPTIMIZE_SIZE),y)
CFLAGS  += -Os
else
CFLAGS  += -O2
endif
LDFLAGS	+= -L$(TOP)/nvram${BCMEX} -lnvram -L$(TOP)/shared -lshared
LDFLAGS += -lgcc_s


vpath %.c $(SRCBASE)/shared $(WLAN_ComponentSrcDirs)

OBJS := wlconf.o bcmwifi_channels.o

all: wlconf

clean:
	rm -f *.o wlconf

install: all
	install -d $(INSTALLDIR)/usr/sbin
	install wlconf $(INSTALLDIR)/usr/sbin
	$(STRIP) $(INSTALLDIR)/usr/sbin/wlconf

wlconf: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
