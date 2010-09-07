AUTOMAKE_OPTIONS = foreign

gssdir = $(libdir)/gss

gss_LTLIBRARIES = libmech_eap.la

libmech_eap_la_CFLAGS  = -DBUILD_GSSEAP_LIB -g -Wall -fno-strict-aliasing @EAP_CFLAGS@ @KRB5_CFLAGS@ @TARGET_CFLAGS@
libmech_eap_la_LDFLAGS = -export-symbols mech_eap.exports -version-info 0:0:0 @EAP_LDFLAGS@ @KRB5_LDFLAGS@ @TARGET_LDFLAGS@
libmech_eap_la_LIBADD  = @EAP_LIBS@ @KRB5_LIBS@

libmech_eap_la_SOURCES =    			\
	accept_sec_context.c			\
	acquire_cred.c				\
	acquire_cred_with_password.c		\
	add_cred.c				\
	add_cred_with_password.c		\
	canonicalize_name.c			\
	compare_name.c				\
	context_time.c				\
	delete_sec_context.c			\
	display_name.c				\
	display_name_ext.c			\
	duplicate_name.c			\
	eap_mech.c				\
	export_name.c				\
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
	inquire_names_for_mech.c		\
	inquire_sec_context_by_oid.c		\
	map_name_to_any.c			\
	process_context_token.c			\
	pseudo_random.c				\
	release_any_name_mapping.c		\
	release_cred.c				\
	release_name.c				\
	set_name_attribute.c			\
	set_cred_option.c			\
	set_sec_context_option.c		\
	store_cred.c				\
	unwrap.c				\
	unwrap_iov.c				\
	util_context.c				\
	util_cksum.c				\
	util_cred.c				\
	util_crypt.c				\
	util_name.c				\
	verify_mic.c				\
	wrap.c					\
	wrap_iov.c				\
	wrap_iov_length.c			\
	wrap_size_limit.c

