AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = gsseap_err.et radsec_err.et \
	mech_eap.exports mech_eap-noacceptor.exports  radius_ad.exports \
	LICENSE AUTHORS mech \
	README.samba4 NOTES radsec.conf


gssincludedir = $(includedir)/gssapi
gssinclude_HEADERS = gssapi_eap.h

EAP_CFLAGS = -I$(srcdir)/../libeap/src -I$(srcdir)/../libeap/src/common -I$(srcdir)/../libeap/src/eap_common  \
	-I$(srcdir)/../libeap/src/utils

if GSSEAP_ENABLE_ACCEPTOR
GSSEAP_EXPORTS = $(srcdir)/mech_eap.exports
else
GSSEAP_EXPORTS = $(srcdir)/mech_eap-noacceptor.exports
endif

gssdir = $(libdir)/gss
gss_LTLIBRARIES = mech_eap.la

if TARGET_WINDOWS
EAP_CFLAGS += -DCONFIG_WIN32_DEFAULTS -DUSE_INTERNAL_CRYPTO
OS_LIBS = -lshell32 -ladvapi32 -lws2_32 -lcomerr32
mech_eap_la_CFLAGS   = -Zi
mech_eap_la_CXXFLAGS = -Zi
else
EAP_CFLAGS += -DEAP_TLS -DEAP_PEAP -DEAP_TTLS -DEAP_MD5 -DEAP_MSCHAPv2 -DEAP_GTC -DEAP_OTP -DEAP_LEAP -DEAP_PSK -DEAP_PAX -DEAP_SAKE -DEAP_GPSK -DEAP_GPSK_SHA256 -DEAP_SERVER_IDENTITY -DEAP_SERVER_TLS -DEAP_SERVER_PEAP -DEAP_SERVER_TTLS -DEAP_SERVER_MD5 -DEAP_SERVER_MSCHAPV2 -DEAP_SERVER_GTC -DEAP_SERVER_PSK -DEAP_SERVER_PAX -DEAP_SERVER_SAKE -DEAP_SERVER_GPSK -DEAP_SERVER_GPSK_SHA256 -DIEEE8021X_EAPOL
OS_LIBS =
mech_eap_la_CFLAGS   = -Werror -Wall -Wunused-parameter
mech_eap_la_CXXFLAGS = -Werror -Wall -Wunused-parameter
endif
mech_eap_la_DEPENDENCIES = $(GSSEAP_EXPORTS)

mech_eap_la_CPPFLAGS = -DBUILD_GSSEAP_LIB -DSYSCONFDIR=\"${sysconfdir}\" -DDATAROOTDIR=\"${datarootdir}\"
mech_eap_la_CFLAGS   += \
			@KRB5_CFLAGS@ @RADSEC_CFLAGS@ @TARGET_CFLAGS@ $(EAP_CFLAGS)
mech_eap_la_CXXFLAGS += \
			@KRB5_CFLAGS@ @RADSEC_CFLAGS@ \
		        @OPENSAML_CXXFLAGS@ @SHIBRESOLVER_CXXFLAGS@ @SHIBSP_CXXFLAGS@ \
			@TARGET_CFLAGS@ $(EAP_CFLAGS)
mech_eap_la_LDFLAGS  = -avoid-version -module \
			-export-symbols $(GSSEAP_EXPORTS) -no-undefined \
			@KRB5_LDFLAGS@ @RADSEC_LDFLAGS@ @TARGET_LDFLAGS@ @OPENSSL_LDFLAGS@

if TARGET_WINDOWS
mech_eap_la_LDFLAGS += -debug
endif

mech_eap_la_LIBADD   = @KRB5_LIBS@ ../libeap/libeap.la @RADSEC_LIBS@ \
		       @OPENSAML_LIBS@ @SHIBRESOLVER_LIBS@ @SHIBSP_LIBS@ @JANSSON_LIBS@ \
		       @OPENSSL_LIBS@
mech_eap_la_SOURCES =    			\
	acquire_cred.c				\
	acquire_cred_with_password.c		\
	add_cred.c				\
	add_cred_with_password.c		\
	authorize_localname.c			\
	canonicalize_name.c			\
	compare_name.c				\
	context_time.c				\
	delete_sec_context.c			\
	display_name.c				\
	display_name_ext.c			\
	display_status.c			\
	duplicate_name.c			\
	eap_mech.c				\
	exchange_meta_data.c			\
	export_name.c				\
	export_sec_context.c			\
	get_mic.c				\
	gsseap_err.c				\
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
	radsec_err.c				\
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
	util_oid.c				\
	util_ordering.c				\
	util_radius.cpp				\
	util_sm.c				\
	util_tld.c				\
	util_token.c				\
	verify_mic.c				\
	wrap.c					\
	wrap_iov.c				\
	wrap_iov_length.c			\
	wrap_size_limit.c \
	gssapiP_eap.h \
	util_attr.h \
	util_base64.h \
	util.h \
	util_json.h \
	util_radius.h \
	util_reauth.h \
	util_saml.h \
	util_shib.h

if LIBMOONSHOT
mech_eap_la_SOURCES += util_moonshot.c
mech_eap_la_CFLAGS  += @LIBMOONSHOT_CFLAGS@
mech_eap_la_LDFLAGS += @LIBMOONSHOT_LDFLAGS@
mech_eap_la_LIBADD  += @LIBMOONSHOT_LIBS@
endif


if GSSEAP_ENABLE_ACCEPTOR

mech_eap_la_SOURCES +=				\
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
	util_json.cpp

if OPENSAML
mech_eap_la_SOURCES += util_saml.cpp
endif

if SHIBRESOLVER
mech_eap_la_SOURCES += util_shib.cpp
endif

endif

BUILT_SOURCES = gsseap_err.c radsec_err.c gsseap_err.h radsec_err.h

if GSSEAP_ENABLE_REAUTH
mech_eap_la_SOURCES += util_reauth.c

if !HEIMDAL
krb5pluginsdir = $(libdir)/krb5/plugins/authdata
krb5plugins_LTLIBRARIES = radius_ad.la

radius_ad_la_CFLAGS  = -Werror -Wall -Wunused-parameter \
			@KRB5_CFLAGS@ $(EAP_CFLAGS) @RADSEC_CFLAGS@ @TARGET_CFLAGS@
radius_ad_la_LDFLAGS = -avoid-version -module \
		       -export-symbols $(srcdir)/radius_ad.exports -no-undefined
radius_ad_la_LIBADD  = @KRB5_LIBS@
radius_ad_la_SOURCES = util_adshim.c authdata_plugin.h
endif
endif

gsseap_err.h gsseap_err.c: gsseap_err.et
	$(COMPILE_ET) $<

radsec_err.h radsec_err.c: radsec_err.et
	$(COMPILE_ET) $<

radsec_err.c: radsec_err.h

clean-generic:
	rm -f gsseap_err.[ch] radsec_err.[ch]
