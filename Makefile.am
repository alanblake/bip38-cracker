INCLUDES = @GLIB_CFLAGS@ -Ipicocoin/include -Iscrypt-jane

bin_PROGRAMS = cracker

cracker_CFLAGS=-O3 -m32 -DSCRYPT_SALSA -DSCRYPT_SHA256
cracker_SOURCES= \
	main.c \
	scrypt-jane/scrypt-jane.c

# OLD scrypt implementation:
# choose either sse or non-sse (ref) for above. SSE gives some speedup.
#	scrypt/crypto/crypto_scrypt-sse.c
#	scrypt/crypto/crypto_scrypt-ref.c
#       scrypt/crypto/sha256.c


cracker_LDADD = picocoin/lib/libccoin.a @GLIB_LIBS@ @CRYPTO_LIBS@ -lpthread
