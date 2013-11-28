AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = libbrowserid.exports

include_HEADERS = browserid.h

if CFBROWSERID
libbrowserid_la_EXPORTS = libbrowserid-cf.exports
else
libbrowserid_la_EXPORTS = libbrowserid.exports
endif

libbrowserid_la_CFLAGS   = -Werror -Wall -Wunused-parameter
libbrowserid_la_CXXFLAGS = -Werror -Wall -Wunused-parameter
libbrowserid_la_DEPENDENCIES = $(libbrowserid_la_EXPORTS)

libbrowserid_la_CPPFLAGS = -DBUILD_GSSBID_LIB -I$(top_srcdir) -I$(top_srcdir)/libbrowserid
libbrowserid_la_SOURCES =   \
    bid_authority.c         \
    bid_base64.c            \
    bid_cache.c             \
    bid_crypto.c            \
    bid_dhparams.c          \
    bid_error.c             \
    bid_fcache.c            \
    bid_context.c           \
    bid_identity.c          \
    bid_jwt.c               \
    bid_mcache.c            \
    bid_openssl.c           \
    bid_ppal.c              \
    bid_reauth.c            \
    bid_rp.c                \
    bid_rcache.c            \
    bid_rverify.c           \
    bid_user.c              \
    bid_util.c              \
    bid_verify.c            \
    bid_x509.c              \
    bid_xrt.c               \
    vers.c

libbrowserid_la_LIBADD   = @JANSSON_LIBS@ @OPENSSL_LIBS@
libbrowserid_la_LDFLAGS  = -export-symbols $(libbrowserid_la_EXPORTS) -no-undefined \
			   @JANSSON_LDFLAGS@ @OPENSSL_LDFLAGS@ @TARGET_LDFLAGS@

if CFNETWORK
libbrowserid_la_SOURCES += bid_cfhttp.c
libbrowserid_la_LDFLAGS += -framework CFNetwork
else
libbrowserid_la_SOURCES += bid_curlhttp.c
libbrowserid_la_LIBADD  += @CURL_LIBS@
libbrowserid_la_LDFLAGS += @CURL_LDFLAGS@
endif

if TARGET_MACOSX
libbrowserid_la_OBJCFLAGS = $(libbrowserid_la_CFLAGS) -fobjc-arc
libbrowserid_la_LDFLAGS += -framework CoreFoundation
libbrowserid_la_SOURCES += bid_wk.m bid_cfjson.m

if TARGET_IOS
libbrowserid_la_LDFLAGS += -framework UIKit -framework Foundation
libbrowserid_la_SOURCES += bid_wkios.m
else
libbrowserid_la_LDFLAGS += -framework WebKit -framework AppKit
libbrowserid_la_SOURCES += bid_wkmac.m
endif

if CFBROWSERID
include_HEADERS += CFBrowserID.h
libbrowserid_la_SOURCES += bid_cf.c
endif

else
libbrowserid_la_SOURCES += bid_stubs.c
endif

lib_LTLIBRARIES = libbrowserid.la

BUILT_SOURCES = vers.c

vers.c: $(top_srcdir)/CVSVersionInfo.txt
	CVSVERSIONDIR=$(top_srcdir) $(top_srcdir)/build/vers_string -v

clean-generic:
	$(RM) vers.c

