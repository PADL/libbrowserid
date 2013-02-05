AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = gssbrowserid_err.et libbrowserid_err.et \
	mech_browserid.exports mech_browserid-noacceptor.exports  \
	AUTHORS

if GSSBID_BUILD_MECH

gssincludedir = $(includedir)/gssapi
gssinclude_HEADERS = gssapi_browserid.h

if GSSBID_ENABLE_ACCEPTOR
GSSBID_EXPORTS = mech_browserid.exports
else
GSSBID_EXPORTS = mech_browserid-noacceptor.exports
endif

gssdir = $(libdir)/gss
gss_LTLIBRARIES = mech_browserid.la

if TARGET_WINDOWS
OS_LIBS = -lshell32 -ladvapi32 -lws2_32 -lcomerr32
mech_browserid_la_CFLAGS   = -Zi
mech_browserid_la_CXXFLAGS = -Zi
else
OS_LIBS =
mech_browserid_la_CFLAGS   = -Werror -Wall -Wunused-parameter
mech_browserid_la_CXXFLAGS = -Werror -Wall -Wunused-parameter
endif
mech_browserid_la_DEPENDENCIES = $(GSSBID_EXPORTS) $(top_builddir)/libbrowserid/libbrowserid.la

mech_browserid_la_CPPFLAGS = -DBUILD_GSSBID_LIB -DSYSCONFDIR=\"${sysconfdir}\" -DDATAROOTDIR=\"${datarootdir}\" -I$(top_srcdir)/libbrowserid
mech_browserid_la_CFLAGS   += \
			@KRB5_CFLAGS@ @TARGET_CFLAGS@ @JANSSON_CFLAGS@
mech_browserid_la_CXXFLAGS += \
			@KRB5_CFLAGS@ @OPENSAML_CXXFLAGS@ @SHIBRESOLVER_CXXFLAGS@ @SHIBSP_CXXFLAGS@ @TARGET_CFLAGS@
mech_browserid_la_LDFLAGS  = -avoid-version -module \
			-export-symbols $(GSSBID_EXPORTS) -no-undefined \
			@KRB5_LDFLAGS@ @JANSSON_LDFLAGS@ @TARGET_LDFLAGS@
if TARGET_WINDOWS
mech_browserid_la_LDFLAGS += -debug
endif

mech_browserid_la_LIBADD   = @KRB5_LIBS@ ../libbrowserid/libbrowserid.la \
		       @OPENSAML_LIBS@ @SHIBRESOLVER_LIBS@ @SHIBSP_LIBS@ @JANSSON_LIBS@

mech_browserid_la_SOURCES =    			\
	acquire_cred.c				\
	add_cred.c				\
	authorize_localname.c			\
	canonicalize_name.c			\
	compare_name.c				\
	context_time.c				\
	delete_sec_context.c			\
	display_name.c				\
	display_name_ext.c			\
	display_status.c			\
	duplicate_name.c			\
	exchange_meta_data.c			\
	export_name.c				\
	export_sec_context.c			\
	get_mic.c				\
	gssbrowserid_err.c			\
	import_name.c				\
	import_sec_context.c			\
	indicate_mechs.c			\
	init_sec_context.c			\
	inquire_attrs_for_mech.c		\
	inquire_context.c			\
	inquire_cred.c				\
	inquire_cred_by_mech.c			\
	inquire_cred_by_oid.c			\
	inquire_mech_for_saslname.c		\
	inquire_mechs_for_name.c		\
	inquire_names_for_mech.c		\
	inquire_saslname_for_mech.c		\
	inquire_sec_context_by_oid.c		\
	process_context_token.c			\
	pseudo_random.c				\
	query_mechanism_info.c			\
	query_meta_data.c			\
	libbrowserid_err.c				\
	release_cred.c				\
	release_name.c				\
	release_oid.c				\
	set_cred_option.c			\
	set_sec_context_option.c		\
	store_cred.c				\
	unwrap.c				\
	unwrap_iov.c				\
	util_buffer.c				\
	util_context.c				\
	util_cksum.c				\
	util_cred.c				\
	util_crypt.c				\
	util_krb.c				\
	util_lucid.c				\
	util_mech.c				\
	util_name.c				\
	util_negoex.c				\
	util_oid.c				\
	util_ordering.c				\
	util_tld.c				\
	util_token.c				\
	verify_mic.c				\
	wrap.c					\
	wrap_iov.c				\
	wrap_iov_length.c			\
	wrap_size_limit.c \
	gssapiP_browserid.h \
	util_attr.h \
	util_base64.h \
	util.h \
	util_json.h \
	util_browserid.h \
	util_reauth.h \
	util_saml.h \
	util_shib.h

if GSSBID_ENABLE_ACCEPTOR

mech_browserid_la_SOURCES +=				\
	accept_sec_context.c			\
	delete_name_attribute.c			\
	export_name_composite.c			\
	get_name_attribute.c			\
	inquire_name.c				\
	map_name_to_any.c			\
	release_any_name_mapping.c		\
	set_name_attribute.c			\
	util_attr.cpp				\
	util_base64.c				\
	util_json.cpp				\
	util_browserid.cpp

if OPENSAML
mech_browserid_la_SOURCES += util_saml.cpp
endif

if SHIBRESOLVER
mech_browserid_la_SOURCES += util_shib.cpp
endif

endif

BUILT_SOURCES = gssbrowserid_err.c libbrowserid_err.c gssbrowserid_err.h libbrowserid_err.h

gssbrowserid_err.h gssbrowserid_err.c: gssbrowserid_err.et
	$(COMPILE_ET) $<

libbrowserid_err.h libbrowserid_err.c: libbrowserid_err.et
	$(COMPILE_ET) $<

libbrowserid_err.c: libbrowserid_err.h

clean-generic:
	rm -f gssbrowserid_err.[ch] libbrowserid_err.[ch]

endif
