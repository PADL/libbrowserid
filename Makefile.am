AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = libbrowserid
if GSSBID_ENABLE_ACCEPTOR
else
SUBDIRS += mech_browserid
endif
EXTRA_DIST = mech_browserid.spec
