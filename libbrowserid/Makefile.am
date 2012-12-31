AUTOMAKE_OPTIONS = foreign

libbrowserid_la_SOURCES =   \
    bid_authority.c         \
    bid_base64.c            \
    bid_context.c           \
    bid_jwt.c               \
    bid_local.c             \
    bid_remote.c            \
    bid_user.c              \
    bid_util.c              \
    bid_webkit.m            \
    bid_verifier.m          \
    vers.c

noinst_LTLIBRARIES = libbrowserid.la

BUILT_SOURCES = vers.c

vers.c: $(top_srcdir)/CVSVersionInfo.txt
	CVSVERSIONDIR=$(top_srcdir) $(top_srcdir)/build/vers_string -v

clean-generic:
	$(RM) vers.c
