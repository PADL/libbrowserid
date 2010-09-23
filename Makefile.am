AUTOMAKE_OPTIONS = foreign

gssincludedir = $(includedir)/gssapi
gssinclude_HEADERS = gssapi_eap.h

gssdir = $(libdir)/gss
gss_LTLIBRARIES = mech_eap.la

mech_eap_la_CPPFLAGS = -DBUILD_GSSEAP_LIB -DSYSCONFDIR=\"${sysconfdir}\"
mech_eap_la_CFLAGS   = -g -Wall -fno-strict-aliasing \
			@EAP_CFLAGS@ @KRB5_CFLAGS@ @TARGET_CFLAGS@
mech_eap_la_CXXFLAGS = -g -Wall \
			@EAP_CFLAGS@ @KRB5_CFLAGS@ @SHIBSP_CXXFLAGS@ \
			@SHIBRESOLVER_CXXFLAGS@ @TARGET_CFLAGS@
mech_eap_la_LDFLAGS  = -avoid-version -module \
			-export-symbols mech_eap.exports -no-undefined \
			@EAP_LDFLAGS@ @KRB5_LDFLAGS@ @TARGET_LDFLAGS@
mech_eap_la_LIBADD   = @EAP_LIBS@ @KRB5_LIBS@ @SHIBSP_LIBS@ \
		       @SHIBRESOLVER_LIBS@ -lfreeradius-client

mech_eap_la_SOURCES =    			\
	accept_sec_context.c			\
	acquire_cred.c				\
	acquire_cred_with_password.c		\
	add_cred.c				\
	add_cred_with_password.c		\
	canonicalize_name.c			\
	compare_name.c				\
	context_time.c				\
	delete_name_attribute.c			\
	delete_sec_context.c			\
	display_name.c				\
	display_name_ext.c			\
	display_status.c			\
	duplicate_name.c			\
	eap_mech.c				\
	export_name.c				\
	export_name_composite.c			\
	export_sec_context.c			\
	get_mic.c				\
	get_name_attribute.c			\
	import_name.c				\
	import_sec_context.c			\
	indicate_mechs.c			\
	init_sec_context.c			\
	inquire_context.c			\
	inquire_cred.c				\
	inquire_cred_by_oid.c			\
	inquire_mechs_for_name.c		\
	inquire_name.c				\
	inquire_names_for_mech.c		\
	inquire_sec_context_by_oid.c		\
	map_name_to_any.c			\
	process_context_token.c			\
	pseudo_random.c				\
	release_any_name_mapping.c		\
	release_cred.c				\
	release_name.c				\
	release_oid.c				\
	set_name_attribute.c			\
	set_cred_option.c			\
	set_sec_context_option.c		\
	store_cred.c				\
	unwrap.c				\
	unwrap_iov.c				\
	util_attr.cpp				\
	util_buffer.c				\
	util_context.c				\
	util_cksum.c				\
	util_cred.c				\
	util_crypt.c				\
	util_krb.c				\
	util_mech.c				\
	util_name.c				\
	util_oid.c				\
	util_ordering.c				\
	util_radius.cpp				\
	util_saml.cpp				\
	util_shib.cpp				\
	util_token.c				\
	verify_mic.c				\
	wrap.c					\
	wrap_iov.c				\
	wrap_iov_length.c			\
	wrap_size_limit.c

if GSSEAP_ENABLE_REAUTH
mech_eap_la_SOURCES += util_reauth.c

krb5pluginsdir = $(libdir)/krb5/plugins/authdata
krb5plugins_LTLIBRARIES = radius_ad.la

radius_ad_la_CFLAGS  = -g -Wall -fno-strict-aliasing \
			  @EAP_CFLAGS@ @KRB5_CFLAGS@ @TARGET_CFLAGS@
radius_ad_la_LDFLAGS = -avoid-version -module \
		       -export-symbols radius_ad.exports -no-undefined
radius_ad_la_LIBADD  = @KRB5_LIBS@
radius_ad_la_SOURCES = util_adshim.c
endif
