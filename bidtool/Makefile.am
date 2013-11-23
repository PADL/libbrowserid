AUTOMAKE_OPTIONS = foreign

CFLAGS += -I../libbrowserid

bin_PROGRAMS = bidtool

bidtool_SOURCES = bidtool.c
bidtool_LDADD = ../libbrowserid/libbrowserid.la @JANSSON_LDFLAGS@ @JANSSON_LIBS@

