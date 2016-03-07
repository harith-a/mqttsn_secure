/* present.c
 * 
 *   Popis:     Implementace blokove sifry PRESENT pro 8-bitovou AVR SmartCard
 *              Prace vznikla jako ukol do predmetu MI-BHW
 *   Autori:    Vojtech Myslivec a Zdenek Novy 
 *              FIT CVUT, unor 2015
 *
 *   Reference: Behem prece bylo cerpano z
 *              [1] A. Bogdanov, C. Paar a kol. PRESENT: An Ultra-Lightweight Block Cipher 
 *                  v Cryptographic Hardware and Embedded Systems - CHES 2007
 *                  (9th International Workshop, Vienna, Austria, September 10-13, 2007. Proceedings).
 *                  Berlin (Germany): Springer Berlin Heidelberg, 2007. 
 *                  Dostupne z http://link.springer.com/chapter/10.1007%2F978-3-540-74735-2_31
 *              [2] Dirk Klose. C PRESENT Implementation (8 Bit) v Implementations (lightweightcrypto.org).
 *                  Dostupne z http://www.lightweightcrypto.org/implementations.php
 *
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>


#define true  0
#define false 1
typedef uint8_t bool;


#define USAGE  "USAGE: \n" \
               "   %s [ -k KEY ]\n" \
               "\n" \
               "      KEY   80-bit key v hexa zapisu\n" \
               "            vychozi hodnota je 00 00 00 00 00 00 00 00 00 00\n    " \
               "\n" \
               "      Program cte Message ze stdin o SIZE 64 bitu (1 blok)    n" \
               "      v hexa zapisu\n" \
               "\n" \
               "EXAMPLE\n" \
               "   echo \"FF FF FF FF FF FF FF FF\" | %s \n" \
               "   echo \"FF FF FF FF FF FF FF FF\" | %s -k \"FF FF FF FF FF F    F FF FF FF FF\"" \
               "\n"


#define BYTE_SIZE   64
#define KEY_SIZE 	10 /* 80 bit / 8 bit */
#define BLOCK_SIZE	8 /* 64 bit / 8 bit */
#define SBOX_SIZE 	16 /* 2^4 substituci (po 4 bitech) */

#define ROUND_COUNT	31

/* sBox je 4-bitovy, nesmi presahnout 0x0F jinak neni chovani definovano */
uint8_t sBox[SBOX_SIZE] = { 0x0C, 0x05, 0x06, 0x0B, 0x09, 0x00, 0x0A, 0x0D, 0x03, 0x0E, 0x0F, 0x08, 0x04, 0x07, 0x01, 0x02 };

uint8_t key[KEY_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t message[BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

uint8_t encryptRound = 0;
char *myKey;
char *myMessage;


static void usage()
{
    fprintf(stderr, "Usage: ./present.out [opts] -k <key> -m <message>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -k <key> \n");
    fprintf(stderr, "  -m <message> \n");
    exit(-1);
}

void printKey( void ) {
   uint8_t i;
   for ( i = 0 ; i < KEY_SIZE ; i++ ) {
      printf( "%02X ", key[KEY_SIZE - 1 - i] );
   }
   printf( "\n" );
}

void printMessage( void ) {
   uint8_t i;
   for ( i = 0 ; i < BLOCK_SIZE ; i++ ) {
      printf( "%02X ", message[BLOCK_SIZE - 1 - i] );
   }
   printf( "\n" );
}


void addRoundKey( ) {
   uint8_t i;
   for ( i = 0 ; i < BLOCK_SIZE ; i++ ) {
      /* xor s rund. keyem */
      /* index u keye je +2 protoze se z 80-ti bitu pouziva 64 nejvyznamnejsich */
      /* melo by byt + KEY_SIZE - BLOCK_SIZE ... */
      message[i] = message[i] ^ key[i + 2];
   }
}

void substitutionLayer( void ) {
   uint8_t i;
   uint8_t nibble1, nibble2;
   for ( i = 0 ; i < BLOCK_SIZE ; i++ ) {
      /* mene vyznamne 4 bity */
      nibble1 = 0x0F & message[i];
      /* vice vyznamne 4 bity */
      nibble2 = 0x0F & ( message[i] >> 4 );  /* maskovani neni potreba, ale ... */

      /* 4-bitove vystupy sBoxu */
      nibble1 = sBox[nibble1] & 0x0F;        /* maskovani neni potreba, ale ... */
      nibble2 = sBox[nibble2] & 0x0F;        /* maskovani neni potreba, ale ... */

      /* rekonstrukce puvodniho byteu zpravy -- substituce byteu */
      nibble2 = ( nibble2 << 4 ) & 0xF0;     /* maskovani neni potreba, ale ... */
      message[i] = nibble2 | nibble1;
   }
}

void permutationLayer( void ) {
   uint8_t sourcePosition, sourceIndex, sourceOffset;
   uint8_t   targetPosition,   targetIndex,   targetOffset;
   uint8_t i, bit, permutation[BLOCK_SIZE];
   for ( i = 0 ; i < BLOCK_SIZE ; i++ ) {
      permutation[i] = 0;
   }

   /* cyklus pres vsechny bity zpravy */
   /* TODO pro prehlednost pocitam rovnou s cislem 63 misto s konstantou BYTE_SIZE - 1  */   
   for ( sourcePosition = 0 ; sourcePosition < BYTE_SIZE ; sourcePosition++ ) {	
      if ( sourcePosition == 63 ) /* vyjimka */	
         targetPosition = 63;
      else	{
         /* algebraick	e vyjadreni permutacni vrstvy, inspirovano z [2] */
         /* schvalne vypocet na dvakrat, aby bylo zajisteno, ze se vejde do 8-bitu  */
         targetPosition = ( 4 * sourcePosition ) % 63;
         targetPosition = ( 4 * targetPosition ) % 63;
      }
      sourceIndex  = sourcePosition / 8;
      sourceOffset = sourcePosition % 8;
      targetIndex  = targetPosition / 8;
      targetOffset = targetPosition % 8;

      bit = ( message[sourceIndex] >> sourceOffset ) & 0x01;
      bit = bit << targetOffset;
      permutation[targetIndex] |= bit;
   }

   /* nahrada zpravy permutaci */
   for ( i = 0 ; i < BLOCK_SIZE ; i++ ) {
      message[i] = permutation[i];
   }
}

void GenerateRoundKey( ) {
   uint8_t i, byte1, byte2, cast1, cast2;
   /* 61-bitovy posun doleva (rol) ----------------------------------------- */
   /* jedna se vlastne o 19-bitovy posun doprava (ror) */
   
   /* nejdriv posun keye o dva bytey = 16 bitu*/
   byte1 = key[0];
   byte2 = key[1];
   for ( i = 0 ; i < KEY_SIZE - 2 ; i++ ) {
      key[i] = key[i + 2];
   }
   key[KEY_SIZE - 2] = byte1;
   key[KEY_SIZE - 1] = byte2;
   
   /* posun keye o dalsi 3 bity */
   byte1 = key[0];
   for ( i = 0 ; i < KEY_SIZE - 1 ; i++ ) {
      cast1 = (     key[i] >> 3 ) & 0x1F;  /* maskovani neni potreba, ale ... */
      cast2 = ( key[i + 1] << 5 ) & 0xE0;  /* maskovani neni potreba, ale ... */
      key[i] = cast1 | cast2;
   }
   cast1 = ( key[KEY_SIZE - 1] >> 3 ) & 0x1F;  /* maskovani neni potreba, ale ... */
   cast2 = ( byte1 << 5 ) & 0xE0;  /* maskovani neni potreba, ale ... */
   key[KEY_SIZE - 1] = cast1 | cast2;

   /* sBox substituce nejvyznamnejsi 4 bity -------------------------------- */
   /* nizsi 4 bity zustanou stejne */
   cast1 =   key[KEY_SIZE - 1] & 0x0F;
   /* vyssi 4 bity */
   cast2 = ( key[KEY_SIZE - 1] >> 4 ) & 0x0F;  /* maskovani neni potreba, ale ... */
   cast2 = sBox[cast2];
   cast2 = ( cast2 << 4 ) & 0xF0;     /* maskovani neni potreba, ale ... */

   key[KEY_SIZE - 1] = cast1 | cast2;
   
   /* xor cisla rundy ------------------------------------------------------ */
   /* (encryptRound je cislovana dle C od 0, musi se tedy pricist 1 ) */
   cast1 = encryptRound + 1;
   /* nejnizsi bit cisla rundy je xorovan s nejvyssim bitem 2. byteu */
   if ( ( cast1 & 0x01 ) == 1 )
      key[1] = key[1] ^ 0x80; 

   /* 4 nejvyssi bity (tedy krome jednoho) cisla rundy jsou xorovany s 4-mi nizsimi bity 3. byteu keye */
   cast1 = ( cast1 >> 1 ) & 0x0F;  /* maskovani neni potreba, ale ... */
   key[2] = key[2] ^ cast1;
}

void encryptPresent( void ) {
   for ( encryptRound = 0 ; encryptRound < ROUND_COUNT; encryptRound++ ) {
      addRoundKey( );      /* addRoundKey( STATE, K[i] ) */
      substitutionLayer( );       /* sBoxLayer( STATE ) */
      permutationLayer( );        /* pLayer( STATE ) */
      GenerateRoundKey( );     /* keySchedule( ) */
   }
   addRoundKey( );
}


/* TODO staticke nacteni ze stringu! */
bool loadkey( const char * parametr ) {
   /* OK, tohle neni pekne a je to staticke pro 10 byteu... se stringama nevim jak lepe */
   if ( 
        KEY_SIZE != sscanf( parametr, "%hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx",
            &key[9],
            &key[8], 
            &key[7], 
            &key[6], 
            &key[5], 
            &key[4], 
            &key[3], 
            &key[2], 
            &key[1], 
            &key[0] 
            ) 

      ) {
      printf( "loadkey(): input error!\n" );
      return false;
   }
   return true;
}

bool loadMessage( const char * parametr ) {
   /* OK, tohle neni pekne a je to staticke pro 10 byteu... se stringama nevim jak lepe */
   if ( 
        BLOCK_SIZE != sscanf( parametr, "%hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx",
            &message[7],
            &message[6],
            &message[5],
            &message[4],
            &message[3],
            &message[2],
            &message[1],
            &message[0]
            ) 
        
      ) {
      printf( "loadMessage(): input error!\n" );
      return false;
   }
   return true;
}

static void parse_opts(int argc, char** argv)
{
    int ch;

    // Parse the options/switches
    while ((ch = getopt(argc, argv, "k:m:?")) != -1)
        switch (ch) {
        case 'k':
            myKey = optarg;
        break;

        case 'm':
            myMessage = optarg;
        break;

        case '?':
        default:
            usage();
        break;
    }
 }

int main( int argc, char ** argv ) {
   
   if ( argc <= 1 ) {
      printf( USAGE, argv[0], argv[0], argv[0] );
      return 1;
   }

   parse_opts(argc, argv);

   if ( loadkey( myKey ) != true ) {
      return 2;
   }

   if ( loadMessage( myMessage ) != true ) {
      return 3;
   }


   printf( "Hello PRESENT!\n" );

   printf( "Message to encrypt: " );
   printMessage( );

   printf( "Encryption key:     " );
   printKey( );

   encryptPresent( );

   printf( "Ciphertext:         " );
   printMessage( );

/*   printf( "0x%02X ", byte );*/
   return 0;
}

