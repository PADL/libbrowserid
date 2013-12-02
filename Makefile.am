AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS =
if TARGET_MACOSX
SUBDIRS += libcfjson
endif
SUBDIRS += libbrowserid bidtool sample
if GSSBID_BUILD_MECH
SUBDIRS += mech_browserid
endif
EXTRA_DIST = mech_browserid.spec
