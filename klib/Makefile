include ../vars.mk

LWIPDIR=		$(VENDORDIR)/lwip
MBEDTLS_DIR=	$(VENDORDIR)/mbedtls

PROGRAMS= \
	cloud_init \
	cloudwatch \
	firewall \
	gcp \
	ntp \
	radar \
	sandbox \
	special_files \
	syslog \
	tls \
	tun \

SRCS-cloud_init= \
	$(CURDIR)/cloud_azure.c \
	$(CURDIR)/cloud_init.c \

SRCS-cloudwatch= \
	$(CURDIR)/aws.c \
	$(CURDIR)/cloudwatch.c \

SRCS-firewall= \
	$(CURDIR)/firewall.c \

SRCS-gcp= \
	$(CURDIR)/gcp.c \

SRCS-ntp= \
	$(CURDIR)/ntp.c \

SRCS-radar= \
	$(CURDIR)/radar.c \

SRCS-sandbox= \
	$(CURDIR)/pledge.c \
	$(CURDIR)/sandbox.c \
	$(CURDIR)/unveil.c \

SRCS-special_files= \
	$(CURDIR)/special_files.c \

SRCS-syslog= \
	$(CURDIR)/syslog.c \

SRCS-tls= \
	$(CURDIR)/mbedtls.c \
	$(SRCS-mbedtls)

SRCS-tun= \
	$(CURDIR)/tun.c \

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

PROGRAMS+= umcg

SRCS-umcg= \
	$(CURDIR)/umcg.c \

endif

ADDITIONAL_PROGRAMS= \
	test/klib \
	test/lock \
	test/page_table \

SRCS-test/klib= \
	$(CURDIR)/test/klib.c

SRCS-test/lock= \
	$(CURDIR)/test/lock.c

SRCS-test/page_table= \
	$(CURDIR)/test/page_table.c

all: klib-syms $(ADDITIONAL_PROGRAMS)

KLIB_SYMS= $(OBJDIR)/klib-syms.lds

DEBUG_STRIP= y
STRIPFLAGS= -g

include ../rules.mk

msg_add_syms=	KLIB_SYMS	$@
cmd_add_syms=	$(foreach prog, $(PROGRAM_BINARIES), $(call add_syms,$(prog)))

# append list of undefined symbols to linker script
define add_syms

	$(Q) $(OBJDUMP) -R $1 | $(SED) -n -E 's/.*(GLOB_DAT|JUMP_SLOT|RISCV_64)[[:space:]]*/EXTERN(/p' | $(SED) -n 's/$$/)/p' >> $(KLIB_SYMS)

endef

klib-syms: $(KLIB_SYMS)

$(KLIB_SYMS): $(PROGRAM_BINARIES)
	$(Q) $(RM) $(KLIB_SYMS)
	$(call cmd,add_syms)
# remove duplicated lines in linker script
	$(Q) $(SED) -i.bak -n 'G; s/\n/&&/; /^\([^\n]*\n\).*\n\1/d; s/\n//; h; P' $(KLIB_SYMS)
# delete linker script backup file
	$(Q) $(RM) $(KLIB_SYMS).bak

ifeq ($(findstring clang,$(COMPILER_VERSION)),clang)
ELF_TARGET=     -target $(ARCH)-elf
CFLAGS+=        $(ELF_TARGET)
endif
LD=             $(CROSS_COMPILE)ld

INCLUDES= \
	-I$(CURDIR) \
	-I$(OUTDIR) \
	-I$(ARCHDIR) \
	-I$(LWIPDIR)/src/include \
	-I$(MBEDTLS_DIR)/include \
	-I$(MBEDTLS_DIR)/library \
	-I$(SRCDIR) \
	-I$(SRCDIR)/http \
	-I$(SRCDIR)/kernel \
	-I$(SRCDIR)/net \
	-I$(SRCDIR)/runtime \
	-I$(SRCDIR)/unix \
	-I$(SRCDIR)/fs \
	-I$(PLATFORMDIR)

DEFINES= \
	-DKERNEL -DKLIB \
	-DMBEDTLS_USER_CONFIG_FILE=\"mbedtls_conf.h\" \

ifneq ($(NOSMP),)
DEFINES+=	-DSPIN_LOCK_DEBUG_NOSMP
else
DEFINES+=	-DSMP_ENABLE
endif

CFLAGS+=	$(KERNCFLAGS) -O3 $(INCLUDES) -fPIC $(DEFINES)

LDFLAGS+=	-shared -Bsymbolic -nostdlib -T$(ARCHDIR)/klib.lds

CLEANFILES+=	$(KLIB_SYMS)
CLEANDIRS+=	$(OUTDIR)/klib/vendor $(OUTDIR)/klib/vendor/mbedtls \
	$(OBJDIR)/bin/test
