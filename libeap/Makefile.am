AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -I$(srcdir)/src -I$(srcdir)/eap_example -I$(srcdir)/src/utils @OPENSSL_CFLAGS@
noinst_HEADERS = \
	src/common/defs.h \
	src/common/eapol_common.h \
	src/common/ieee802_11_common.h \
	src/common/ieee802_11_defs.h \
	src/common/privsep_commands.h \
	src/common/version.h \
	src/common/wpa_common.h \
	src/common/wpa_ctrl.h

EXTRA_DIST = src/tls/libtommath.c

SOURCES_BOTH = src/eap_common/eap_peap_common.c
SOURCES_BOTH += src/eap_common/eap_psk_common.c
SOURCES_BOTH += src/eap_common/eap_pax_common.c
SOURCES_BOTH += src/eap_common/eap_sake_common.c
SOURCES_BOTH += src/eap_common/eap_gpsk_common.c
SOURCES_BOTH += src/eap_common/chap.c \
	src/eap_common/chap.h \
	src/eap_common/eap_common.h \
	src/eap_common/eap_defs.h \
	src/eap_common/eap_fast_common.h \
	src/eap_common/eap_gpsk_common.h \
	src/eap_common/eap_ikev2_common.h \
	src/eap_common/eap_pax_common.h \
	src/eap_common/eap_peap_common.h \
	src/eap_common/eap_psk_common.h \
	src/eap_common/eap_pwd_common.h \
	src/eap_common/eap_sake_common.h \
	src/eap_common/eap_sim_common.h \
	src/eap_common/eap_tlv_common.h \
	src/eap_common/eap_ttls.h \
	src/eap_common/eap_wsc_common.h \
	src/eap_common/ikev2_common.h


SOURCES_peer = src/eap_peer/eap_tls.c
SOURCES_peer += src/eap_peer/eap_peap.c
SOURCES_peer += src/eap_peer/eap_ttls.c
SOURCES_peer += src/eap_peer/eap_md5.c
SOURCES_peer += src/eap_peer/eap_mschapv2.c
SOURCES_peer += src/eap_peer/mschapv2.c
SOURCES_peer += src/eap_peer/eap_otp.c
SOURCES_peer += src/eap_peer/eap_gtc.c
SOURCES_peer += src/eap_peer/eap_leap.c
SOURCES_peer += src/eap_peer/eap_psk.c
SOURCES_peer += src/eap_peer/eap_pax.c
SOURCES_peer += src/eap_peer/eap_sake.c
SOURCES_peer += src/eap_peer/eap_gpsk.c
SOURCES_peer += src/eap_peer/eap.c
SOURCES_peer += src/eap_common/eap_common.c
SOURCES_peer += src/eap_peer/eap_methods.c
SOURCES_peer += src/eap_peer/eap_tls_common.c \
	src/eap_peer/eap_config.h \
	src/eap_peer/eap_fast_pac.h \
	src/eap_peer/eap.h \
	src/eap_peer/eap_i.h \
	src/eap_peer/eap_methods.h \
	src/eap_peer/eap_tls_common.h \
	src/eap_peer/ikev2.h \
	src/eap_peer/mschapv2.h \
	src/eap_peer/tncc.h

AM_CFLAGS = -DEAP_TLS
AM_CFLAGS += -DEAP_PEAP
AM_CFLAGS += -DEAP_TTLS
AM_CFLAGS += -DEAP_MD5
AM_CFLAGS += -DEAP_MSCHAPv2
AM_CFLAGS += -DEAP_GTC
AM_CFLAGS += -DEAP_OTP
AM_CFLAGS += -DEAP_LEAP
AM_CFLAGS += -DEAP_PSK
AM_CFLAGS += -DEAP_PAX
AM_CFLAGS += -DEAP_SAKE
AM_CFLAGS += -DEAP_GPSK -DEAP_GPSK_SHA256

AM_CFLAGS += -DEAP_SERVER_IDENTITY
AM_CFLAGS += -DEAP_SERVER_TLS
AM_CFLAGS += -DEAP_SERVER_PEAP
AM_CFLAGS += -DEAP_SERVER_TTLS
AM_CFLAGS += -DEAP_SERVER_MD5
AM_CFLAGS += -DEAP_SERVER_MSCHAPV2
AM_CFLAGS += -DEAP_SERVER_GTC
AM_CFLAGS += -DEAP_SERVER_PSK
AM_CFLAGS += -DEAP_SERVER_PAX
AM_CFLAGS += -DEAP_SERVER_SAKE
AM_CFLAGS += -DEAP_SERVER_GPSK -DEAP_SERVER_GPSK_SHA256

AM_CFLAGS += -DIEEE8021X_EAPOL
AM_CFLAGS += -DCONFIG_IPV6

AM_CFLAGS += -DCONFIG_INTERNAL_LIBTOMMATH
AM_CFLAGS += -DCONFIG_INTERNAL_SHA1
AM_CFLAGS += -DEAP_TLS_OPENSSL
AM_CFLAGS += -DPKCS12_FUNCS

UTILS_SRCS = src/utils/base64.c \
	src/utils/common.c \
	src/utils/ip_addr.c \
	src/utils/radiotap.c \
	src/utils/trace.c \
	src/utils/uuid.c \
	src/utils/wpa_debug.c \
	src/utils/wpabuf.c \
	src/utils/os_unix.c \
	src/utils/radius_utils.c \
src/utils/radius_utils.h \
	src/utils/base64.h \
	src/utils/build_config.h \
	src/utils/common.h \
	src/utils/eloop.h \
	src/utils/includes.h \
	src/utils/ip_addr.h \
	src/utils/list.h \
	src/utils/os.h \
	src/utils/pcsc_funcs.h \
	src/utils/radiotap.h \
	src/utils/radiotap_iter.h \
	src/utils/state_machine.h \
	src/utils/trace.h \
	src/utils/uuid.h \
	src/utils/wpabuf.h \
	src/utils/wpa_debug.h


CRYPTO_SRCS = \
    src/crypto/aes-cbc.c \
    src/crypto/aes-ctr.c \
    src/crypto/aes-eax.c \
    src/crypto/aes-encblock.c \
    src/crypto/aes-omac1.c \
    src/crypto/aes-unwrap.c \
    src/crypto/aes-wrap.c \
    src/crypto/md5.c \
    src/crypto/md5-non-fips.c \
    src/crypto/milenage.c \
    src/crypto/ms_funcs.c \
    src/crypto/sha1.c \
    src/crypto/sha1-pbkdf2.c \
    src/crypto/sha1-tlsprf.c \
    src/crypto/sha1-tprf.c \
    src/crypto/sha256.c \
    src/crypto/crypto_openssl.c \
    src/crypto/tls_openssl.c \
    src/crypto/aes.h \
    src/crypto/aes_i.h \
    src/crypto/aes_wrap.h \
    src/crypto/crypto.h \
    src/crypto/md5.h \
    src/crypto/milenage.h \
    src/crypto/ms_funcs.h \
    src/crypto/sha1.h \
    src/crypto/sha256.h \
    src/crypto/tls.h

TLS_SRCS = \
    src/tls/asn1.c \
    src/tls/bignum.c \
    src/tls/pkcs1.c \
    src/tls/pkcs5.c \
    src/tls/pkcs8.c \
    src/tls/rsa.c \
    src/tls/tlsv1_client.c \
    src/tls/tlsv1_client_read.c \
    src/tls/tlsv1_client_write.c \
    src/tls/tlsv1_common.c \
    src/tls/tlsv1_cred.c \
    src/tls/tlsv1_record.c \
    src/tls/tlsv1_server.c \
    src/tls/tlsv1_server_read.c \
    src/tls/tlsv1_server_write.c \
    src/tls/x509v3.c \
    src/tls/asn1.h \
    src/tls/bignum.h \
    src/tls/pkcs1.h \
    src/tls/pkcs5.h \
    src/tls/pkcs8.h \
    src/tls/rsa.h \
    src/tls/tlsv1_client.h \
    src/tls/tlsv1_client_i.h \
    src/tls/tlsv1_common.h \
    src/tls/tlsv1_cred.h \
    src/tls/tlsv1_record.h \
    src/tls/tlsv1_server.h \
    src/tls/tlsv1_server_i.h \
    src/tls/x509v3.h 

libeap_la_SOURCES = $(SOURCES_BOTH) $(SOURCES_peer) $(UTILS_SRCS) $(CRYPTO_SRCS)

noinst_LTLIBRARIES = libeap.la
