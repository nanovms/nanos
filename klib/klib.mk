KLIB_DIR= $(ROOTDIR)/klib

MBEDTLS_DIR=	$(VENDORDIR)/mbedtls

KLIBS= \
	azure \
	cloud_init \
	cloudwatch \
	digitalocean \
	firewall \
	gcp \
	ntp \
	radar \
	sandbox \
	shmem \
	special_files \
	strace \
	syslog \
	tmpfs \
	tls \
	tun \

SRCS-azure= \
	$(KLIB_DIR)/azure.c \
	$(KLIB_DIR)/azure_diagnostics.c \

SRCS-cloud_init= \
	$(KLIB_DIR)/cloud_azure.c \
	$(KLIB_DIR)/cloud_init.c \
	$(KLIB_DIR)/net_utils.c \
	$(KLIB_DIR)/xml.c \

SRCS-cloudwatch= \
	$(KLIB_DIR)/aws.c \
	$(KLIB_DIR)/cloudwatch.c \

SRCS-digitalocean= \
	$(KLIB_DIR)/crc32.c \
	$(KLIB_DIR)/digitalocean.c \

SRCS-firewall= \
	$(KLIB_DIR)/firewall.c \

SRCS-gcp= \
	$(KLIB_DIR)/gcp.c \

SRCS-ntp= \
	$(KLIB_DIR)/ntp.c \

SRCS-radar= \
	$(KLIB_DIR)/radar.c \

SRCS-sandbox= \
	$(KLIB_DIR)/pledge.c \
	$(KLIB_DIR)/sandbox.c \
	$(KLIB_DIR)/unveil.c \

SRCS-shmem= \
	$(KLIB_DIR)/shmem.c \

SRCS-special_files= \
	$(KLIB_DIR)/special_files.c \

SRCS-strace= \
	$(KLIB_DIR)/strace.c \
	$(KLIB_DIR)/strace_file.c \
	$(KLIB_DIR)/strace_mem.c \
	$(KLIB_DIR)/strace_misc.c \

SRCS-syslog= \
	$(KLIB_DIR)/syslog.c \

SRCS-tls= \
	$(KLIB_DIR)/mbedtls.c \
	$(SRCS-mbedtls)

SRCS-tmpfs= \
	$(KLIB_DIR)/tmpfs.c \

SRCS-tun= \
	$(KLIB_DIR)/tun.c \

SRCS-mbedtls= $(SRCS-mbedtls-crypto) $(SRCS-mbedtls-x509) $(SRCS-mbedtls-tls)

SRCS-mbedtls-crypto= \
	$(MBEDTLS_DIR)/library/aes.c \
	$(MBEDTLS_DIR)/library/arc4.c \
	$(MBEDTLS_DIR)/library/aria.c \
	$(MBEDTLS_DIR)/library/asn1parse.c \
	$(MBEDTLS_DIR)/library/asn1write.c \
	$(MBEDTLS_DIR)/library/base64.c \
	$(MBEDTLS_DIR)/library/bignum.c \
	$(MBEDTLS_DIR)/library/blowfish.c \
	$(MBEDTLS_DIR)/library/camellia.c \
	$(MBEDTLS_DIR)/library/ccm.c \
	$(MBEDTLS_DIR)/library/chacha20.c \
	$(MBEDTLS_DIR)/library/chachapoly.c \
	$(MBEDTLS_DIR)/library/cipher.c \
	$(MBEDTLS_DIR)/library/cipher_wrap.c \
	$(MBEDTLS_DIR)/library/cmac.c \
	$(MBEDTLS_DIR)/library/constant_time.c \
	$(MBEDTLS_DIR)/library/ctr_drbg.c \
	$(MBEDTLS_DIR)/library/des.c \
	$(MBEDTLS_DIR)/library/dhm.c \
	$(MBEDTLS_DIR)/library/ecdh.c \
	$(MBEDTLS_DIR)/library/ecdsa.c \
	$(MBEDTLS_DIR)/library/ecjpake.c \
	$(MBEDTLS_DIR)/library/ecp.c \
	$(MBEDTLS_DIR)/library/ecp_curves.c \
	$(MBEDTLS_DIR)/library/entropy.c \
	$(MBEDTLS_DIR)/library/entropy_poll.c \
	$(MBEDTLS_DIR)/library/gcm.c \
	$(MBEDTLS_DIR)/library/havege.c \
	$(MBEDTLS_DIR)/library/hkdf.c \
	$(MBEDTLS_DIR)/library/hmac_drbg.c \
	$(MBEDTLS_DIR)/library/md.c \
	$(MBEDTLS_DIR)/library/md2.c \
	$(MBEDTLS_DIR)/library/md4.c \
	$(MBEDTLS_DIR)/library/md5.c \
	$(MBEDTLS_DIR)/library/memory_buffer_alloc.c \
	$(MBEDTLS_DIR)/library/nist_kw.c \
	$(MBEDTLS_DIR)/library/oid.c \
	$(MBEDTLS_DIR)/library/padlock.c \
	$(MBEDTLS_DIR)/library/pem.c \
	$(MBEDTLS_DIR)/library/pk.c \
	$(MBEDTLS_DIR)/library/pk_wrap.c \
	$(MBEDTLS_DIR)/library/pkcs12.c \
	$(MBEDTLS_DIR)/library/pkcs5.c \
	$(MBEDTLS_DIR)/library/pkparse.c \
	$(MBEDTLS_DIR)/library/pkwrite.c \
	$(MBEDTLS_DIR)/library/platform.c \
	$(MBEDTLS_DIR)/library/platform_util.c \
	$(MBEDTLS_DIR)/library/poly1305.c \
	$(MBEDTLS_DIR)/library/psa_crypto.c \
	$(MBEDTLS_DIR)/library/psa_crypto_aead.c \
	$(MBEDTLS_DIR)/library/psa_crypto_cipher.c \
	$(MBEDTLS_DIR)/library/psa_crypto_client.c \
	$(MBEDTLS_DIR)/library/psa_crypto_driver_wrappers.c \
	$(MBEDTLS_DIR)/library/psa_crypto_ecp.c \
	$(MBEDTLS_DIR)/library/psa_crypto_hash.c \
	$(MBEDTLS_DIR)/library/psa_crypto_mac.c \
	$(MBEDTLS_DIR)/library/psa_crypto_rsa.c \
	$(MBEDTLS_DIR)/library/psa_crypto_se.c \
	$(MBEDTLS_DIR)/library/psa_crypto_slot_management.c \
	$(MBEDTLS_DIR)/library/psa_its_file.c \
	$(MBEDTLS_DIR)/library/ripemd160.c \
	$(MBEDTLS_DIR)/library/rsa.c \
	$(MBEDTLS_DIR)/library/rsa_internal.c \
	$(MBEDTLS_DIR)/library/sha1.c \
	$(MBEDTLS_DIR)/library/sha256.c \
	$(MBEDTLS_DIR)/library/sha512.c \
	$(MBEDTLS_DIR)/library/threading.c \
	$(MBEDTLS_DIR)/library/version.c \
	$(MBEDTLS_DIR)/library/xtea.c \

SRCS-mbedtls-x509= \
	$(MBEDTLS_DIR)/library/certs.c \
	$(MBEDTLS_DIR)/library/pkcs11.c \
	$(MBEDTLS_DIR)/library/x509.c \
	$(MBEDTLS_DIR)/library/x509_crt.c \

SRCS-mbedtls-tls= \
	$(MBEDTLS_DIR)/library/ssl_cache.c \
	$(MBEDTLS_DIR)/library/ssl_ciphersuites.c \
	$(MBEDTLS_DIR)/library/ssl_cli.c \
	$(MBEDTLS_DIR)/library/ssl_cookie.c \
	$(MBEDTLS_DIR)/library/ssl_msg.c \
	$(MBEDTLS_DIR)/library/ssl_srv.c \
	$(MBEDTLS_DIR)/library/ssl_ticket.c \
	$(MBEDTLS_DIR)/library/ssl_tls.c \

ifeq ($(ARCH),x86_64)

KLIBS+= umcg

SRCS-umcg= \
	$(KLIB_DIR)/umcg.c \

endif

KLIBS+= \
	test/klib \
	test/lock \
	test/page_table \

SRCS-test/klib= \
	$(KLIB_DIR)/test/klib.c

SRCS-test/lock= \
	$(KLIB_DIR)/test/lock.c

SRCS-test/page_table= \
	$(KLIB_DIR)/test/page_table.c

KLIB_INCLUDES= \
	-I$(KLIB_DIR) \
	-I$(MBEDTLS_DIR)/include \
	-I$(MBEDTLS_DIR)/library \

KLIB_DEFINES= \
	-DKLIB \
	-DMBEDTLS_USER_CONFIG_FILE=\"mbedtls_conf.h\" \

KLIB_CFLAGS= $(CFLAGS) $(KLIB_INCLUDES) -fPIC $(KLIB_DEFINES)

KLIB_LDFLAGS= -shared -Bsymbolic -nostdlib -T$(ARCHDIR)/klib.lds

KLIB_BINARIES= $(foreach prog, $(KLIBS), $(OBJDIR)/bin/$(prog))
KLIB_SYMS= $(OBJDIR)/klib-syms.lds

CLEANFILES+=	$(KLIB_SYMS)
CLEANDIRS+=		\
	$(OBJDIR)/vendor/mbedtls \
	$(OBJDIR)/bin/test
