AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -I$(srcdir)/src -I$(srcdir)/eap_example -I$(srcdir)/src/utils 

SOURCES_BOTH = src/eap_common/eap_peap_common.c
SOURCES_BOTH += src/eap_common/eap_psk_common.c
SOURCES_BOTH += src/eap_common/eap_pax_common.c
SOURCES_BOTH += src/eap_common/eap_sake_common.c
SOURCES_BOTH += src/eap_common/eap_gpsk_common.c
SOURCES_BOTH += src/eap_common/chap.c

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
SOURCES_peer += src/eap_peer/eap_tls_common.c
CFLAGS += -DEAP_TLS
CFLAGS += -DEAP_PEAP
CFLAGS += -DEAP_TTLS
CFLAGS += -DEAP_MD5
CFLAGS += -DEAP_MSCHAPv2
CFLAGS += -DEAP_GTC
CFLAGS += -DEAP_OTP
CFLAGS += -DEAP_LEAP
CFLAGS += -DEAP_PSK
CFLAGS += -DEAP_PAX
CFLAGS += -DEAP_SAKE
CFLAGS += -DEAP_GPSK -DEAP_GPSK_SHA256

CFLAGS += -DEAP_SERVER_IDENTITY
CFLAGS += -DEAP_SERVER_TLS
CFLAGS += -DEAP_SERVER_PEAP
CFLAGS += -DEAP_SERVER_TTLS
CFLAGS += -DEAP_SERVER_MD5
CFLAGS += -DEAP_SERVER_MSCHAPV2
CFLAGS += -DEAP_SERVER_GTC
CFLAGS += -DEAP_SERVER_PSK
CFLAGS += -DEAP_SERVER_PAX
CFLAGS += -DEAP_SERVER_SAKE
CFLAGS += -DEAP_SERVER_GPSK -DEAP_SERVER_GPSK_SHA256

CFLAGS += -DIEEE8021X_EAPOL
CFLAGS += -DCONFIG_IPV6

CFLAGS += -DCONFIG_INTERNAL_LIBTOMMATH
CFLAGS += -DCONFIG_CRYPTO_INTERNAL


UTILS_SRCS = src/utils/base64.c \
	src/utils/common.c \
	src/utils/ip_addr.c \
	src/utils/radiotap.c \
	src/utils/trace.c \
	src/utils/uuid.c \
	 src/utils/wpa_debug.c \
	src/utils/wpabuf.c
CRYPTO_SRCS = \
    src/crypto/aes-cbc.c \
    src/crypto/aes-ctr.c \
    src/crypto/aes-eax.c \
    src/crypto/aes-encblock.c \
    src/crypto/aes-internal.c \
    src/crypto/aes-internal-dec.c \
    src/crypto/aes-internal-enc.c \
    src/crypto/aes-omac1.c \
    src/crypto/aes-unwrap.c \
    src/crypto/aes-wrap.c \
    src/crypto/des-internal.c \
    src/crypto/dh_group5.c \
    src/crypto/dh_groups.c \
    src/crypto/md4-internal.c \
    src/crypto/md5.c \
    src/crypto/md5-internal.c \
    src/crypto/md5-non-fips.c \
    src/crypto/milenage.c \
    src/crypto/ms_funcs.c \
    src/crypto/rc4.c \
    src/crypto/sha1.c \
    src/crypto/sha1-internal.c \
    src/crypto/sha1-pbkdf2.c \
    src/crypto/sha1-tlsprf.c \
    src/crypto/sha1-tprf.c \
    src/crypto/sha256.c \
    src/crypto/sha256-internal.c \
    src/crypto/crypto_internal.c \
    src/crypto/crypto_internal-cipher.c \
    src/crypto/crypto_internal-modexp.c \
    src/crypto/crypto_internal-rsa.c \
    src/crypto/tls_internal.c \
    src/crypto/fips_prf_internal.c

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
    src/tls/x509v3.c

libeap_la_SOURCES = $(SOURCES_BOTH) $(UTILS_SRCS) $(CRYPTO_SRCS) $(TLS_SRCS)

noinst_LTLIBRARIES = libeap.la
