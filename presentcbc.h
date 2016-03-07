/* decrypt.h*/

// Include-file
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define true  0
#define false 1
#define BYTE_SIZE   64
#define KEY_SIZE 	10 /* 80 bit / 8 bit */
#define BLOCK_SIZE	8 /* 64 bit / 8 bit */
#define SBOX_SIZE 	16 /* 2^4 substituci (po 4 bitech) */
typedef uint8_t bool;

bool loadkey( const char*);
bool loadMessage( const char*);

void printMessage( uint8_t* ,size_t);

void decrypt( void );
void decryptP(uint8_t*, const uint8_t*, uint8_t *);
void encryptt(void);
void encryptP( uint8_t *, const uint8_t *, uint8_t *);

void cbc_encrypt( uint8_t *, const uint8_t *, uint8_t *, size_t );
void cbc_decrypt( uint8_t *, const uint8_t *, uint8_t *, size_t );

void padStr(char* str, uint8_t *padded,int *len);
void presentencrypt(char *str, uint8_t *retstr);
void presentdecrypt(uint8_t *retstr, char *str);




