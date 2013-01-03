AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = bidtool

libbrowserid_la_CPPFLAGS = -DBUILD_GSSBID_LIB -I$(top_srcdir) -I$(top_srcdir)/mech_browserid
libbrowserid_la_SOURCES =   \
    bid_authority.c         \
    bid_base32.c            \
    bid_base64.c            \
    bid_cache.c             \
    bid_fcache.c            \
    bid_context.c           \
    bid_identity.c          \
    bid_jwt.c               \
    bid_openssl.c           \
    bid_reauth.c            \
    bid_rcache.c            \
    bid_rverify.c           \
    bid_user.c              \
    bid_util.c              \
    bid_webkit.m            \
    bid_verify.c            \
    vers.c

noinst_LTLIBRARIES = libbrowserid.la

BUILT_SOURCES = vers.c

vers.c: $(top_srcdir)/CVSVersionInfo.txt
	CVSVERSIONDIR=$(top_srcdir) $(top_srcdir)/build/vers_string -v

clean-generic:
	$(RM) vers.c

bidtool_SOURCES = bidtool.c
bidtool_LDADD = $(noinst_LTLIBRARIES) @KRB5_LDFLAGS@ @JANSSON_LDFLAGS@ @CURL_LDFLAGS@ @OPENSSL_LDFLAGS@ @KRB5_LIBS@ @TARGET_LDFLAGS@ @JANSSON_LIBS@ @CURL_LIBS@ @OPENSSL_LDFLAGS@
