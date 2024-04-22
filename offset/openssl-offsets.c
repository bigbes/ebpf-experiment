#include <stdio.h>

#include <crypto/bio/bio_local.h>
#include <ssl/ssl_local.h>

int main() {
    printf("OpenSSL version %s\n", OPENSSL_VERSION_TEXT);

    #ifndef OPENSSL_VERSION_NUMBER 
        #error "OPENSSL_VERSION_NUMBER not defined"
    #endif

    #if OPENSSL_VERSION_NUMBER < 0x30200000L
        printf("  version offset: 0x%lx\n", offsetof(struct ssl_st, version));
        printf("\n");
        printf("  rbio offset: 0x%lx\n", offsetof(struct ssl_st, rbio));
        printf("  wbio offset: 0x%lx\n", offsetof(struct ssl_st, wbio));
        printf("  bio fd offset: 0x%lx\n", offsetof(struct bio_st, num));
    #else
        printf("  version offset: 0x%lx\n", offsetof(struct ssl_connection_st, version));
        printf("\n");
        printf("  rbio offset: 0x%lx\n", offsetof(struct ssl_connection_st, rbio));
        printf("  wbio offset: 0x%lx\n", offsetof(struct ssl_connection_st, wbio));
        printf("  bio fd offset: 0x%lx\n", offsetof(struct bio_st, num));
    #endif
}
