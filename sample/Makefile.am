AUTOMAKE_OPTIONS = foreign

CFLAGS += -I../libbrowserid

noinst_PROGRAMS = bidget bidverify

bidget_SOURCES = bidget.c
bidget_LDADD = ../libbrowserid/libbrowserid.la

bidverify_SOURCES = bidverify.c
bidverify_LDADD = ../libbrowserid/libbrowserid.la

if CFBROWSERID
noinst_PROGRAMS += bidcfget bidcfverify

bidcfget_OBJCFLAGS = -I../libbrowserid -fobjc-arc
bidcfget_SOURCES = bidcfget.m
bidcfget_LDADD = ../libbrowserid/libbrowserid.la

bidcfverify_OBJCFLAGS = -I../libbrowserid -fobjc-arc
bidcfverify_SOURCES = bidcfverify.m
bidcfverify_LDADD = ../libbrowserid/libbrowserid.la
endif

