/* cracker for casascius's contest, details here:

   https://bitcointalk.org/index.php?topic=128699.0

Repurposed for reddit contest:

   http://www.reddit.com/r/Bitcoin/comments/1zkcya/lets_see_how_long_it_takes_to_crack_a_4_digit/

Updated to handle other crypto's

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

#define NUM_THREADS 16

void print_hex(char * hex, size_t len) {
    int i;
    for(i=0; i<len; i++) {
        printf("%.02x",(unsigned char)hex[i]);
    }
}

/*
Select cryptocurrency to crack by uncommenting the relevant defines
*/

#define CRACKTESTPASSWORD "Satoshi"

// Bitcoin
#define NETWORKVERSION 0x00
#define PRIVATEKEYPREFIX 0x80
#define CRACKTEST "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd"

// // DigiByte
// #define NETWORKVERSION 0x1e
// #define PRIVATEKEYPREFIX 0x9e
// #define CRACKTEST "6PfNwTiBBoRe4PqWRw48Bt2GsTmUPpQJ4SxhGGnRMVEWBLDCLVK3bkY2JS"


// // Paycoin
// #define NETWORKVERSION 0x37
// #define PRIVATEKEYPREFIX 0xb7
// #define CRACKTEST "6PfXBuS1vVhtnpkCsAQtMBd93iJBaip61WiQYkp1HfYzwa1UwWsL5rBDk3"


/* End cryptocurrency select */

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
    btcAddress = bp_pubkey_get_address(&wallet, NETWORKVERSION);

    /*
    printf("address: %s\r\n",btcAddress->str);
    */

    unsigned char checkHash[32];
    bu_Hash(checkHash, btcAddress->str, strlen(btcAddress->str));

    /* printf("checkhash: %.02x%.02x%.02x%.02x\r\n",
    checkHash[0],checkHash[1],checkHash[2],checkHash[3]); */

    if(!memcmp(&b58dec->str[3],checkHash,4)) {

        // Format private key to WIF
        unsigned char hash1[SHA256_DIGEST_LENGTH];
        bu_Hash(hash1, finalKey, 32);
        unsigned char hash2[SHA256_DIGEST_LENGTH];
        bu_Hash(hash2, hash1, 32);

        unsigned char wif_data[1+32+4];
        wif_data[0] = PRIVATEKEYPREFIX;
        memcpy(wif_data+1, finalKey, 32);
        memcpy(wif_data+33, hash2, 4);

    	GString *wif = base58_encode_check(PRIVATEKEYPREFIX, true, finalKey, sizeof(finalKey));

/*
        char cmd[512];
        cmd[0]=0;
        strcat(cmd, "curl 'https://blockchain.info/merchant/");
        strcat(cmd, wif->str);
        strcat(cmd, "/payment?to=1DirbaioGK4T7vVwa4dfHFHYJ7B6GZ1oEh&amount=19990000'");
        system(cmd);
*/

        printf("!!!!!!!!!!!!!!!!!!!!\r\n");
        printf("!!hash match found!!\r\n");
        printf("!!  public is %s  !!\r\n", btcAddress->str);
        printf("!!  privkey is %s  !!\r\n", wif->str);
        printf("!!!!!!!!!!!!!!!!!!!!\r\n");
        print_hex(pKey_pass, strlen(pKey_pass));
        printf("\r\n!!!!!!!!!!!!!!!!!!!!\r\n");
        return 0;
    }

    return 1;
}

pthread_mutex_t coderoll_mutex;
long unsigned int number_tested;

void coderoll(char * currentPass) {
    pthread_mutex_lock(&coderoll_mutex);
    if(fgets(currentPass, 200, stdin))
        currentPass[strlen(currentPass)-1]=0;
    else
        currentPass[0] = 0;

    number_tested ++;
    if(number_tested % 25 == 0) {
        printf("total tested: %lu, current code: %s\n",number_tested, currentPass);
        fflush(stdout);
    }

    pthread_mutex_unlock(&coderoll_mutex);
}

char pKey[256];

void * crackthread(void * ctx) {
    char currentPass[256];
    while(true) {
        coderoll(currentPass);
        if(currentPass[0] == 0)
            break;

        if(!crack(pKey, currentPass)) {
            printf("found password: %s\r\n",currentPass);
            exit(0);
        }
    }
}

int main(int argc, char * argv[]) {
    if(argc != 2) {
        fprintf(stderr,"Usage: crack 6Pf...\n");
        fprintf(stderr,"Passwords to try are read from stdin, one per line.\n");
        exit(1);
    }

    strcpy(pKey, argv[1]);

    int i;
    pthread_t threads[NUM_THREADS];
    number_tested = 0;
    printf("casascius bip38 private key brute forcer\r\n");
    OpenSSL_add_all_algorithms();

    /* make sure the crack function is working */
    if(crack(CRACKTEST,CRACKTESTPASSWORD)) {
    	fprintf(stderr,"the crack function is not working, sorry.\n");
        exit(1);
    }


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
