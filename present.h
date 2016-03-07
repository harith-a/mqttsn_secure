/* decrypt.h*/

// Include-file
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
void printKey( void );
void printMessage( const char* );

void decrypt( void );
void decryptP(char** , char* );
void encryptt(void);
void encryptP(char **, char *);



