/* cracker for casascius's contest, details here:

   https://bitcointalk.org/index.php?topic=128699.0

Repurposed for reddit contest:

   http://www.reddit.com/r/Bitcoin/comments/1zkcya/lets_see_how_long_it_takes_to_crack_a_4_digit/
*/

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <glib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include "scrypt-jane.h"
#include "ccoin/base58.h"
#include "ccoin/key.h"
#include "ccoin/address.h"

#define NUM_THREADS 8

void print_hex(char * hex, size_t len) {
    int i;
    for(i=0; i<len; i++) {
        printf("%.02x",(unsigned char)hex[i]);
    }
}

#define PASSFACTOR_SIZE 32
#define PASSPHRASE_MAGIC_SIZE 8
#define PASSPHRASE_SIZE (PASSPHRASE_MAGIC_SIZE + OWNERSALT_SIZE + 33)
#define DERIVED_SIZE 64
#define ADDRESSHASH_SIZE 4
#define OWNERSALT_SIZE 8

int crack(const char * pKey, char * pKey_pass) {
    int i;
    uint8_t passfactor[PASSFACTOR_SIZE];

    /* printf("testing key %s, %s\r\n",pKey, pKey_pass); */

    GString * b58dec;
    b58dec = base58_decode_check(NULL,pKey);

    if(b58dec) {
        /*
        printf("%s", "base58decode of encrypted key: ");
        print_hex(b58dec->str,b58dec->len);
        printf("%s", "\r\n");
        printf("flagByte: %.02x addresshash:%.02x%.02x%.02x%.02x ownersalt:",
            (unsigned char)b58dec->str[2], (unsigned char)b58dec->str[3],
            (unsigned char)b58dec->str[4], (unsigned char)b58dec->str[5],
            (unsigned char)b58dec->str[6]);
        print_hex(&b58dec->str[3+ADDRESSHASH_SIZE], OWNERSALT_SIZE);
        printf("\r\n");
        */
        memset(passfactor,0,PASSFACTOR_SIZE);
        scrypt( pKey_pass, strlen(pKey_pass),
                &(b58dec->str[3+ADDRESSHASH_SIZE]), OWNERSALT_SIZE,
                13 /*16384*/, 3 /*8*/, 3 /*8*/, passfactor, PASSFACTOR_SIZE );
        /*
        printf("%s", "passfactor: ");
        print_hex(passfactor, PASSFACTOR_SIZE);
        printf("%s", "\r\n");
        */
    } else {
        fprintf(stderr,"%s","cannot b58 decode private key.");
        exit(1);
    }

    // compute EC point (passpoint) using passfactor
    struct bp_key ec_point;
    if(!bp_key_init(&ec_point)) {
        fprintf(stderr,"%s","cannot init EC point key");
        exit(3);
    }
    if(!bp_key_secret_set(&ec_point,passfactor,PASSFACTOR_SIZE)) {
        fprintf(stderr,"%s","cannot set EC point from passfactor");
        exit(3);
    }

    // get the passpoint as bytes
    unsigned char * passpoint;
    unsigned int passpoint_len;

    if(!bp_pubkey_get(&ec_point,(void *)&passpoint,&passpoint_len)) {
        fprintf(stderr,"%s","cannot get pubkey for EC point");
        exit(4);
    }

    /*
    printf("len is %d, passpoint: ", passpoint_len);
    print_hex(passpoint,passpoint_len);
    printf("%s", "\r\n");
    */

    /*
    // check: generate the passphrase
    char passphrase_bytes[PASSPHRASE_SIZE];
    char passphrase_magic[] = { 0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x53 };
    memset(passphrase_bytes,0,PASSPHRASE_SIZE);
    memcpy(passphrase_bytes, passphrase_magic, PASSPHRASE_MAGIC_SIZE);
    memcpy(passphrase_bytes + PASSPHRASE_MAGIC_SIZE,
        &b58dec->str[3+ADDRESSHASH_SIZE], OWNERSALT_SIZE);
    memcpy(passphrase_bytes + PASSPHRASE_MAGIC_SIZE + OWNERSALT_SIZE,
        passpoint, passpoint_len);
    GString * passphrase_g = base58_encode_check(0,false,
        passphrase_bytes, PASSPHRASE_SIZE);
        printf("Passphrase: %s\r\n\r\n", passphrase_g->str);
    */

    // now we need to decrypt seedb
    uint8_t encryptedpart2[16];
    memset(encryptedpart2,0,16);
    memcpy(encryptedpart2,
           &b58dec->str[3 + ADDRESSHASH_SIZE + OWNERSALT_SIZE + 8],16);
    uint8_t encryptedpart1[16];
    memset(encryptedpart1,0,16);
    memcpy(encryptedpart1,
           &b58dec->str[3 + ADDRESSHASH_SIZE + OWNERSALT_SIZE],8);

    unsigned char derived[DERIVED_SIZE];
    // get the encryption key for seedb using scrypt
    // with passpoint as the key, salt is addresshash+ownersalt
    unsigned char derived_scrypt_salt[ADDRESSHASH_SIZE + OWNERSALT_SIZE];
    memcpy(derived_scrypt_salt,
           &b58dec->str[3], ADDRESSHASH_SIZE); // copy the addresshash
    memcpy(derived_scrypt_salt+ADDRESSHASH_SIZE,
           &b58dec->str[3+ADDRESSHASH_SIZE], OWNERSALT_SIZE); // copy the ownersalt
    scrypt( passpoint, passpoint_len,
            derived_scrypt_salt, ADDRESSHASH_SIZE+OWNERSALT_SIZE,
            9/*1024*/, 0/*1*/, 0/*1*/, derived, DERIVED_SIZE );

    //get decryption key
    unsigned char derivedhalf2[DERIVED_SIZE/2];
    memcpy(derivedhalf2, derived+(DERIVED_SIZE/2), DERIVED_SIZE/2);

    unsigned char iv[32];
    memset(iv,0,32);
    EVP_CIPHER_CTX d;
    EVP_CIPHER_CTX_init(&d);
    EVP_DecryptInit_ex(&d, EVP_aes_256_ecb(), NULL, derivedhalf2, iv);
    EVP_CIPHER_CTX_set_padding(&d, 0);

    unsigned char unencryptedpart2[32];
    int decrypt_len;
    EVP_DecryptUpdate(&d, unencryptedpart2, &decrypt_len, encryptedpart2, 16);
    assert(decrypt_len == 16);
    for(i=0; i<16; i++) {
        unencryptedpart2[i] ^= derived[i + 16];
    }
    unsigned char unencryptedpart1[32];
    memcpy(encryptedpart1+8, unencryptedpart2, 8);

    EVP_DecryptUpdate(&d, unencryptedpart1, &decrypt_len, encryptedpart1, 16);
    assert(decrypt_len == 16);
    for(i=0; i<16; i++) {
        unencryptedpart1[i] ^= derived[i];
    }

    EVP_DecryptFinal_ex(&d, unencryptedpart1+decrypt_len, &decrypt_len);
    EVP_CIPHER_CTX_cleanup(&d);

    // recover seedb
    unsigned char seedb[24];
    memcpy(seedb, unencryptedpart1, 16);
    memcpy(&(seedb[16]), &(unencryptedpart2[8]), 8);

    // turn seedb into factorb (factorb = SHA256(SHA256(seedb)))
    unsigned char factorb[32];
    //printf("seedb:   "); print_hex(seedb, 24); printf("\n");
    bu_Hash(factorb, seedb, 24);
    //printf("factorb: "); print_hex(factorb, 32); printf("\n");

    // multiply by passfactor (ec_point_pub)
    const EC_GROUP * ec_group = EC_KEY_get0_group(ec_point.k);
    const EC_POINT * ec_point_pub = EC_KEY_get0_public_key(ec_point.k);
    BIGNUM * bn_passfactor = BN_bin2bn(passfactor,32,BN_new());
    BIGNUM * bn_factorb = BN_bin2bn(factorb,32,BN_new());
    BIGNUM * bn_res = BN_new();
    BIGNUM * bn_final = BN_new();
    BIGNUM * bn_n = BN_new();
    BN_CTX * ctx = BN_CTX_new();
    EC_GROUP_get_order(ec_group, bn_n, ctx);
    BN_mul(bn_res, bn_passfactor, bn_factorb, ctx);
    BN_mod(bn_final, bn_res, bn_n, ctx);

    unsigned char finalKey[32];
    memset(finalKey, 0, 32);
    int n = BN_bn2bin(bn_final, finalKey);

    BN_clear_free(bn_passfactor);
    BN_clear_free(bn_factorb);
    BN_clear_free(bn_res);
    BN_clear_free(bn_n);
    BN_clear_free(bn_final);

    // we have a private key! check hash
    /*
    printf("have private key: ");
    print_hex(finalKey, 32);
    printf("%s", "\r\n");
    */

    // turn it into a real address
    struct bp_key wallet;
    if(!bp_key_init(&wallet)) {
        fprintf(stderr,"%s","cannot init wallet key");
        exit(10);
    }
    if(!bp_key_secret_set(&wallet,finalKey,32)) {
        fprintf(stderr,"%s","cannot init wallet key");
        exit(10);
    }
    EC_KEY_set_conv_form(wallet.k, POINT_CONVERSION_UNCOMPRESSED);

    /*
    unsigned char * pubKey;
    size_t pubKeylen;
    bp_pubkey_get(&wallet, ((void **) &pubKey), &pubKeylen);

    printf("pubkey len: %d hex: ",pubKeylen);
    print_hex(pubKey,pubKeylen);
    printf("%s","\r\n");
    */

    GString * btcAddress;
    btcAddress = bp_pubkey_get_address(&wallet, 0);

    /*
    printf("address: %s\r\n",btcAddress->str);
    */

    unsigned char checkHash[32];
    bu_Hash(checkHash, btcAddress->str, strlen(btcAddress->str));

    /* printf("checkhash: %.02x%.02x%.02x%.02x\r\n",
    checkHash[0],checkHash[1],checkHash[2],checkHash[3]); */

    if(!memcmp(&b58dec->str[3],checkHash,4)) {
        printf("!!!!!!!!!!!!!!!!!!!!\r\n");
        printf("!!hash match found!!\r\n");
        printf("!!  key is %s  !!\r\n", pKey_pass);
        printf("!!!!!!!!!!!!!!!!!!!!\r\n");
        print_hex(pKey_pass, strlen(pKey_pass));
        printf("\r\n!!!!!!!!!!!!!!!!!!!!\r\n");
        return 0;
    }

    return 1;
}

pthread_mutex_t coderoll_mutex;
long unsigned int number_tested;

#define KEYSPACE 6

// 5-character password for AaAaJ test vector
#if KEYSPACE == 0
int coderoll(char * currentPass) {
    static char pass[6] = { "AaAaA" }; // the current password being checked
    int i;
    for (i=4; i>=0; i--) {
        pass[i]++;
        if (i&1) {
            if (pass[i] <= 'z') break;
            pass[i] = 'a';
        } else {
            if (pass[i] <= 'Z') break;
            pass[i] = 'A';
        }
    }
    strcpy(currentPass,pass);
    return -1;
}

#elif KEYSPACE == 1

// numeric pins [done]
int coderoll(char *pass) {
    static int pin = 0000;
    // make a random 4-character password
    sprintf(pass, "%04d", pin++);
    if (pin>9999) { exit(1); }
    return pin;
}

#elif KEYSPACE == 2

// one byte printable UTF-8 -- that is, 32 <= c <= 127
// (keyspace 6 does this better)
int coderoll(char *pass) {
    static unsigned char pin[] = { ' ', ' ', '%', 'o', 0 };
    strcpy(pass, pin);
    do {
        if ((++pin[3]) == 0x80) {
            pin[3] = ' ';
            if ((++pin[2]) == 0x80) {
                pin[2] = ' ';
                if ((++pin[1]) == 0x80) {
                    pin[1] = ' ';
                    if ((++pin[0]) == 0x80) {
                        exit(1);
                    }
                }
            }
        }
    } while (pin[0] >= '0' && pin[0] <= '9' &&
             pin[1] >= '0' && pin[1] <= '9' &&
             pin[2] >= '0' && pin[2] <= '9' &&
             pin[3] >= '0' && pin[3] <= '9');
    return -1;
}

#elif KEYSPACE == 3

// a bitcoin quantity [done]
int coderoll(char *pass) {
    // from https://en.bitcoin.it/wiki/Bitcoin_symbol
    // http://fortawesome.github.io/Font-Awesome/icon/btc/
#define ALPHABET_SIZE 23
    static const char *alphabet[ALPHABET_SIZE] = {
        "\xef\x85\x9a",  // '\uf15a'
        "B\xe2\x83\xa6", // 'B\u20e6' (COMBINING DOUBLE VERTICAL STROKE OVERLAY)
        "\xE0\xB8\xBF",  // '\u0e3f' (THAI CURRENCY SYMBOL BAHT)
        "\xc9\x83", // '\u0243' (LATIN CAPITAL LETTER B WITH STROKE)
        "\xe1\x97\xb8", // '\u15f8' (CANADIAN SYLLABICS CARRIER KHEE)
        "B\xe2\x83\xab", // 'B\u20EB' (COMBINING LONG DOUBLE SOLIDUS OVERLAY)
        "\xe2\x92\xb7", // '\u24b7' (CIRCLED LATIN CAPITAL LETTER B)
        "\xe2\x93\x91", // '\u24d1' (CIRCLED LATIN SMALL LETTER B)
        "\xe1\xb4\x83", // '\u1d03' (LATIN LETTER SMALL CAPITAL BARRED B)
        "\xe2\x93\xa2", // '\u24e2' (CIRCLED LATIN SMALL LETTER S)
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        ".", " ", "!"
    };
    static int code = 0;

    do {
        char *p = pass;
        int n = code++, i;
        for (i=0; i<4; i++) {
            strcpy(p, alphabet[n % ALPHABET_SIZE]);
            p += strlen(p);
            n = n / ALPHABET_SIZE;
        }
        if (n != 0) { exit(1); }
    } while (pass[0] >= '0' && pass[0] <= '9' &&
             pass[1] >= '0' && pass[1] <= '9' &&
             pass[2] >= '0' && pass[2] <= '9' &&
             pass[3] >= '0' && pass[3] <= '9');
    return code;
#undef ALPHABET_SIZE
}

#elif KEYSPACE == 4

// random unicode junk [done]
int coderoll(char *pass) {
    // from https://en.bitcoin.it/wiki/Bitcoin_symbol
    // http://fortawesome.github.io/Font-Awesome/icon/btc/
#define ALPHABET_SIZE 10
    static const char *alphabet[ALPHABET_SIZE] = {
        "\xf0\x9f\x90\xb6",
        "\xf0\x9f\x90\x95",
        "\xf0\x9f\x90\xbe",
        "\xf0\x9f\x92\xa9",
        "\xe2\x98\x83",
        "\xe2\x9c\xa1",
        "\xe2\x9c\x88",
        "\xf0\x9f\x8f\xa2",
        "\xef\x85\x9a",  // '\uf15a'
        "\xE0\xB8\xBF"  // '\u0e3f' (THAI CURRENCY SYMBOL BAHT)
        // others? '\u21ce' cf http://www.reddit.com/r/Bitcoin/comments/1q7inm/this_paper_wallet_now_contains_0225_btc_and_is/cd9zfyx
    };
    static int code = 0;

    do {
        char *p = pass;
        int n = code++, i;
        for (i=0; i<4; i++) {
            strcpy(p, alphabet[n % ALPHABET_SIZE]);
            p += strlen(p);
            n = n / ALPHABET_SIZE;
        }
        if (n != 0) { exit(1); }
    } while (pass[0] >= '0' && pass[0] <= '9' &&
             pass[1] >= '0' && pass[1] <= '9' &&
             pass[2] >= '0' && pass[2] <= '9' &&
             pass[3] >= '0' && pass[3] <= '9');
    return code;
#undef ALPHABET_SIZE
}

#elif KEYSPACE == 5

// dictionary words, doge words [done]
int coderoll(char *pass) {
#if 1
# include "words.h"
#else
# include "dogewords.h"
#endif
    static int index = 0;
    int n = index++;
    if (!words[n]) { exit(1); }
    strcpy(pass, words[n]);
    return index;
}

#elif KEYSPACE == 6
/* incremental search into the upper reaches of unicode land */
#define STARTVALUE 0
char *write_utf8(char *s, unsigned v) {
    // xxx private-use characters? (6,400 + 65534 + 65534 of these)
    // xxx format characters? (147 of these)
    if (v <= 0x1F) { return NULL; } // control code
    if (v>=0x7F && v<=0x9F) { return NULL; } // control code
    if (v <= 0x7F) {
        *s++ = v;
    } else if (v <= 0x7FF) {
        *s++ = 0xC0 | (v>>6);
        *s++ = 0x80 | (v & 0x3F);
    } else if (v <= 0xFFFF) {
        if (v>=0xD800 && v<=0xDFFF) { return NULL; } // surrogate pairs
        if (v>=0xFDD0 && v<=0xFDEF) { return NULL; } // non-character
        if (v==0xFFFE || v==0xFFFF) { return NULL; } // non-character
        *s++ = 0xE0 | (v>>12);
        *s++ = 0x80 | ((v>>6) & 0x3F);
        *s++ = 0x80 | (v & 0x3F);
    } else if (v <= 0x1FFFFF) {
        if ((v&0xFFFE) == 0xFFFE) { return NULL; } // non-character
        *s++ = 0xF0 | (v>>18);
        *s++ = 0x80 | ((v>>12) & 0x3F);
        *s++ = 0x80 | ((v>>6) & 0x3F);
        *s++ = 0x80 | (v & 0x3F);
    } else {
        exit(1); // no more characters
    }
    return s;
}
int coderoll(char *pass) {
#define PLEN 4
    static unsigned code[PLEN] = { 0, 0, 0, 0 };
    static int counter = 0;
 again:
    counter++;
    // what's the highest value
    unsigned max = 0;
    int i, j;
    for (i=0; i<PLEN; i++) {
        if (code[i] > max) {
            max = code[i];
        }
    }
    // increment first digit which isn't at max
    for (i=0; i<PLEN; i++) {
        if (code[i] < max) {
            if (++code[i] < max) {
                goto done;
            }
            // newly at max, reset & go to next digit
            code[i] = 0;
        }
    }
    // ok, we need the next permutation of the MAX digits
    // (the other digits should be zero at this point.)
    // M - - -
    // - M - -
    // - - M -
    // - - - M
    // M M - -
    // M - M -
    // M - - M
    // - M M -
    // - M - M
    // - - M M
    // M M M -
    // M M - M
    // M - M M
    // - M M M
    // M M M M
    unsigned skip = 0;
    for (i=PLEN-1; i>=0; i--) {
        if (code[i] == max) {
            skip++;
            if (i + 1 + skip <= PLEN) {
                code[i++] = 0;
                goto write_max;
            }
        }
    }
    // increase the number of m's
    skip++; i = 0;
    if (i + skip <= PLEN) { goto write_max; }
    // increase max
    max++; skip = 1;
    printf("-- expanding key search to %d --\n", max);
    if ((max+32) > 0x10FFFF) { exit(1); } // not likely!
 write_max:
    for ( ; i < PLEN; i++) {
        code[i] = (skip && skip--) ? max : 0;
    }
 done:
    // initial startup
    if (counter < STARTVALUE) { goto again; }
    // skip all-numeric passwords
    for (i=0;i<PLEN;i++) {
        char c = code[i]+32;
        if (c<'0' || c>'9') break;
    }
    if (i==PLEN) { goto again; } // we already searched these in KEYSPACE 1
    // convert array of unicode values into utf8
    char *p = pass;
    for (i=0; i<PLEN; i++) {
        p = write_utf8(p, code[i]+32); // skip control characters
        if (!p) { goto again; /* bad unicode value, skip it! */ }
    }
    *p = 0;
    return counter;
}

#else
# error Must define a keyspace.
#endif

void coderoll_wrapper(char *pass) {
    pthread_mutex_lock(&coderoll_mutex);
    number_tested ++;

    int index = coderoll(pass);

   if(number_tested % 10 == 0) {
        printf("total tested: %lu, current code: %s [%d]\r\n",number_tested, pass, index);
        fflush(stdout);
    }
    pthread_mutex_unlock(&coderoll_mutex);
}

void * crackthread(void * ctx) {
    const char * pKey;
    char currentPass[17];
    pKey = (const char *)ctx;
    while(true) {
        coderoll_wrapper(currentPass);
        if(!crack(pKey, currentPass)) {
            printf("found password: %s\r\n",currentPass);
            exit(0);
        }
    }
}

int main(int argc, char * argv[]) {
    int i;
    pthread_t threads[NUM_THREADS];
    number_tested = 0;
    printf("casascius bip38 private key brute forcer\r\n");
    OpenSSL_add_all_algorithms();

#if 0
    /* takes a single command line arg. */
    /* if passed in, this is the starting string to check instead of AaAaA */
    if(argc > 1) {
        strncpy(pass,argv[1],5);
    } else {
        strncpy(pass,"AaAaA",5);
    }
#endif

    /* make sure the crack function is working */
    if(crack("6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd","Satoshi")){
    	fprintf(stderr,"the crack function is not working, sorry.\n");
        exit(1);
    }

    /* the target encrypted private key to crack. */
    //const char pKey[] = "6PfTokDpyZUYwaVg37aZZ67MvD1bTyrCyjrjacz1XAgfVndWjZSsxLuDrE"; // official Casascius contest key
    const char pKey[] = "6PfQoEzqbz3i2LpHibYnwAspwBwa3Nei1rU7UH9yzfutXT7tyUzV8aYAvG"; // reddit contest key
    //const char pKey[] = "6PfMxA1n3cqYarHoDqPRPLpBBJGWLDY1qX94z8Qyjg7XAMNZJMvHLqAMyS"; // test key that decrypts with AaAaJ
    //const char pKey[] = "6PfLk3DLTTXwrK6T8PJuLDtRek2WNmdPCd4ht6ShBJ823MBXVqC4a9VEew"; // 4 *digit* key: http://www.reddit.com/r/Bitcoin/comments/1zkcya/lets_see_how_long_it_takes_to_crack_a_4_digit/cfw79rw

    printf("Attempting to crack:\n%s\n", pKey);

    pthread_mutex_t coderoll_mutex = PTHREAD_MUTEX_INITIALIZER;

    for(i=0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, crackthread, (void *)pKey);
    }

    for(i=0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_exit(NULL);
    EVP_cleanup();
    return 0;
}
