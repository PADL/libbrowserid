AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = bidtool

CPPFLAGS = -I$(top_srcdir)/libbrowserid

if TARGET_MACOSX
CPPFLAGS += -I$(top_srcdir)/libcfjson
endif

bidtool_SOURCES = bidtool.c
bidtool_LDADD = ../libbrowserid/libbrowserid.la @JANSSON_LDFLAGS@ @JANSSON_LIBS@

