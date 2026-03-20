//#include <algorithm>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>
#include "baseP.h"

typedef struct {
    BIGNUM *k;
    BIGNUM *base;
    BIGNUM *p;
    BIGNUM *K;
} dh_instance;

dh_instance dh_createInstance(BIGNUM *k, BIGNUM *base, BIGNUM *p, BN_CTX *ctx) {
    
    BIGNUM *r = BN_new();

    if (r == NULL) {printf("dh_createInstance: BigNum error in generating r!\n"); return (dh_instance) {k, base, p, NULL};}

    BN_mod_exp(r, base, k, p, ctx);
    return (dh_instance) {k, base, p, r};
}

BIGNUM *dh_getSecret(dh_instance *instance, BIGNUM *K, BN_CTX *ctx) {

    BIGNUM *r = BN_new();

    if (r == NULL) {printf("dh_getSecret: BigNum error in generating r!\n"); return NULL;}
    
    BN_mod_exp(r, K, instance->k, instance->p, ctx);
    return r;
}

void printUCharAsHex(const unsigned char *arr, unsigned int size, unsigned char flag) {
    for (int i = 0; i < size; i++) {
        printf("%02X", arr[i]);
    }
    if (flag) printf("\n");
}

unsigned int returnMin(unsigned int val, unsigned int min) {
    if (val < min) {
        return min;
    }
    return val;
}

unsigned char hex_to_byte(char high, char low) {
    unsigned char hi = (high >= '0' && high <= '9') ? high - '0' :
                       (high >= 'A' && high <= 'F') ? high - 'A' + 10 :
                       (high >= 'a' && high <= 'f') ? high - 'a' + 10 : 0;

    unsigned char lo = (low >= '0' && low <= '9') ? low - '0' :
                       (low >= 'A' && low <= 'F') ? low - 'A' + 10 :
                       (low >= 'a' && low <= 'f') ? low - 'a' + 10 : 0;

    return (hi << 4) | lo;
}

void hexStringToUCharArr(unsigned char *hexString, unsigned char *output, unsigned int lenHexArr) {
    if (lenHexArr % 2 == 0) {
        for (int i = 0; i < lenHexArr; i+=2) {
            output[i/2] = hex_to_byte(hexString[i], hexString[i+1]);
        }
    }
}


int main() {
    // GENERATE RANDOM PRIVATE KEY
    unsigned char privateKey[256];
    RAND_bytes(privateKey, 256);

    // PRINT PRIVATE KEY
    printf("\nYour k (Private Key): ");
    printUCharAsHex(privateKey, 2, 0);
    printf("............");
    printUCharAsHex(privateKey + 255-2, 2, 1);

    // GENERATE BIG NUM CONTEXT
    BN_CTX *ctx = BN_CTX_new();


    // CREATE PRIVATE KEY BIGNUM
    BIGNUM *BN_privateKey = BN_new();
    BN_bin2bn(privateKey, 256, BN_privateKey);
    
    // CREATE BASE (g) BIGNUM
    BIGNUM *BN_base = BN_new();
    BN_hex2bn(&BN_base, DH_BASE);
    
    // CREATE PRIME (p) BIGNUM
    BIGNUM *BN_p = BN_new();
    BN_hex2bn(&BN_p, DH_P);


    // CHECK FOR NULL
    if (BN_privateKey == NULL || BN_base == NULL || BN_p == NULL) {printf("BigNum error of generating (g, p, k)\n"); return -1;}


    // CREATE DIFFIE HELLMAN OBJECT
    dh_instance instance = dh_createInstance(BN_privateKey, BN_base, BN_p, ctx);

    // GET PUBLIC KEY IN HEX
    char *publicKeyHEX = BN_bn2hex(instance.K);


    // START KEY EXCHANGE
    printf("The agreed p is \n%.8s...\n\n", DH_P);
    printf("The agreed base is \n%s\n\n", DH_BASE);
    printf("\n========================KEY EXCHANGE========================\n\n");
    printf("Your Public Key is \n%s\n\n", publicKeyHEX);

    // RECOVER OTHER PUBLIC KEY
    char receiverPubKey[2048];
    printf("\nReceiver's public key:\n");
    scanf("%s", (char *) &receiverPubKey);

    
    // PARSE RECEIVER's PUBLIC KEY INTO BIGNUM
    BIGNUM *BN_receiverPubKey = BN_new();
    
    if (BN_receiverPubKey == NULL) {printf("BigNum error of generating BN_receiverPubKey\n"); return -1;}
    
    BN_hex2bn(&BN_receiverPubKey, receiverPubKey);

    
    // DERIVE SERCET FROM DH EXCHANGE
    BIGNUM *BN_DHSecret = dh_getSecret(&instance, BN_receiverPubKey, ctx);

    char *DHSecretHEX = BN_bn2hex(BN_DHSecret);


    // HASH SECRET
    unsigned char secretHash[SHA256_DIGEST_LENGTH];

    SHA256((const unsigned char*) DHSecretHEX, strlen(DHSecretHEX), secretHash);

    printf("\nYour Shared Secret (Hashed):\n");


    // PRINT HIDDEN HASH
    printUCharAsHex(secretHash, 2, 0);
    printf("............");
    printUCharAsHex(secretHash + SHA256_DIGEST_LENGTH-2, 2, 1);
    printf("\n============================================================\n\n");


    // START MESSAGE LOOP
    while (1) {

        // GET OPERATION
        char op;
        printf(" -=> Send or receive message? (s = send | r = receive): ");
        scanf(" %c", &op);

        if (op == 's') {

            //
            // ENCRYPTION OPERATION
            //


            // CREATE MESSAGE BUFFER
            unsigned char messageBuff[4096];

            // GET MESSAGE UNTIL NEWLINE
            printf("\n    > Enter your message: ");
            scanf(" %[^\n]", messageBuff);
            getchar();
            

            // CALCULATE MESSAGE LENGTH
            unsigned int messageLen = strlen(messageBuff);


            // CALCULATE BLOCK SIZE
            unsigned int blockSize = 16*returnMin((messageLen+15)/16, 1); 


            // CREATE MESSAGE OBJECT AND COPY MESSAGE
            char *message = calloc(blockSize, 1);
            
            if (message == NULL) {printf("Calloc Fail While Sending Message\n"); return -1;}

            memcpy(message, messageBuff, messageLen);
            
            RAND_bytes((unsigned char *)message+messageLen+1, blockSize-(messageLen+1));


            // GENERATE RANDOM IV
            unsigned char iv[16];

            RAND_bytes(iv, 16);

            // ALLOCATE 16 BYTES FOR IV IN CIPHERTEXT AND CREATE CIPHERTEXT OBJECT IN MEMORY
            unsigned int ciphertextSize = 16 + blockSize;

            unsigned char *ciphertext = malloc(ciphertextSize);
            
            if (ciphertext == NULL) {printf("Malloc Fail While Sending Message\n"); return -1;}

            // COPY IV INTO START OF CIPHER TEXT
            memcpy(ciphertext, iv, 16);


            // CALCULATE ENCRYPTION KEY FROM HASH(SECRET)
            AES_KEY enc_key;

            AES_set_encrypt_key(secretHash, 256, &enc_key);


            // ENCRYPT
            AES_cbc_encrypt((const unsigned char *) message, ciphertext+16, blockSize, &enc_key, iv, AES_ENCRYPT);


            // PRINT CIPHER TEXT
            printf("\n\n    > Your Cipher Text Is: ");
            printUCharAsHex(ciphertext, ciphertextSize, 1);
            printf("\n");


        } else if (op == 'r') {

            // ALLOCATE CIPHERTEXT HEX INPUT BUFFER
            unsigned char ciphertextHEXBuff[8192];

            // GET CIPHER TEXT
            printf("\n    > Enter cipher text: ");
            scanf(" %[^\n]", ciphertextHEXBuff);
            getchar();


            // GET CIPHERTEXT LEN
            unsigned int ciphertextLen = strlen((char *)ciphertextHEXBuff)/2;

            // CHECK IF CIPHERTEXT HAS VALID SIZE
            if (ciphertextLen % 16 == 0) {

                // ALLOCATE AND FILL CIPHERTEXT BYTE BUFFER
                unsigned char *ciphertextBuff = malloc(ciphertextLen);

                if (ciphertextBuff == NULL) {printf("Malloc Fail While Receiving Message\n"); return -1;}

                hexStringToUCharArr(ciphertextHEXBuff, ciphertextBuff, ciphertextLen*2);



                // COPY ACTUAL CIPHERTEXT INTO CIPHERTEXT OBJECT
                unsigned char *ciphertext = malloc(ciphertextLen-16);

                if (ciphertext == NULL) {printf("Malloc Fail While Receiving Message\n"); return -1;}

                memcpy(ciphertext, ciphertextBuff+16, ciphertextLen-16);


                // COPY IV FROM CIPHERTEXTBUFF
                unsigned char iv[16];

                memcpy(iv, ciphertextBuff, 16);
                

                // CREATE DECRYPTED OBJECT
                unsigned char *decrypted = malloc(ciphertextLen-16);

                if (decrypted == NULL) {printf("Malloc Fail While Receiving Message\n"); return -1;}


                // CREATE DECRYPTION KEY
                AES_KEY dec_key;

                AES_set_decrypt_key(secretHash, 256, &dec_key);


                // DECRYPT
                AES_cbc_encrypt(ciphertext, decrypted, ciphertextLen-16, &dec_key, iv, AES_DECRYPT);

                // PRINT DECRYPTED MESSAGE
                printf("\n\n    > Decrypted message: %s\n\n", decrypted);


            } else {

                // IF CIPHERTEXT SIZE NOT A MULTIPLE OF 16 IT IS INVALID
                printf("\n    >! Invalid cipher text\n\n");
            };


        }




    }
    


    // EXIT LOOP
    int exit;
    printf("\nEnter any number to exit\n");
    scanf("\n%i", &exit);

    return 0;
}
