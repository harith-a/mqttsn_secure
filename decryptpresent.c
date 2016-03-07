
// Include-file
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define true  0
#define false 1
typedef uint8_t bool;

#define BYTE_SIZE   64
#define KEY_SIZE 	10 /* 80 bit / 8 bit */
#define BLOCK_SIZE	8 /* 64 bit / 8 bit */
#define SBOX_SIZE 	16 /* 2^4 substituci (po 4 bitech) */

#define ROUND_COUNT	31

char *myKey;
char *myMessage;

//	Input values
  	uint8_t key[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	volatile uint8_t message[] = {0x45,0x84,0x22,0x7b,0x38,0xc1,0x79,0x55};


static void usage()
{
    fprintf(stderr, "Usage: ./present.out [opts] -k <key> -m <message>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -k <key> \n");
    fprintf(stderr, "  -m <message> \n");
    exit(-1);
}

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

void decrypt(void)
{
	const uint8_t sBox4[] = {
							0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2
							};

	const uint8_t invsBox4[] = {
							   0x5,0xe,0xf,0x8,0xc,0x1,0x2,0xd,0xb,0x4,0x6,0x3,0x0,0x7,0x9,0xa
							   };

//	Counter
	uint8_t i = 0;
//	pLayer variables
	uint8_t position = 0;
	uint8_t element_source = 0;
	uint8_t bit_source = 0;
	uint8_t element_destination = 0;
	uint8_t bit_destination = 0;
	uint8_t temp_pLayer[8];
//	Key scheduling variables
	uint8_t round = 0;
	uint8_t save1;
	uint8_t save2;
	uint8_t subkey[32][8];
//	****************** Encryption **************************
//	****************** Key Scheduling **********************
//	key precomputation
	for(i=2;i<=9;i++)
	{
		subkey[0][i-2] = key[i];
	}
	do
	{	
		i=0;
		save1  = key[0];
		save2  = key[1];	
		i = 0;
		do
		{
			key[i] = key[i+2];
			i++;
		}
		while(i<8);
		key[8] = save1;
		key[9] = save2;
		i = 0;
		save1 = key[0] & 7;
		do
		{
			key[i] = key[i] >> 3 | key[i+1] << 5;			
			i++;
		}
		while(i<9);
		key[9] = key[9] >> 3 | save1 << 5;

		key[9] = sBox4[key[9]>>4]<<4 | (key[9] & 0xF);

		if((round+1) % 2 == 1)
			key[1] ^= 128;
		key[2] = ((((round+1)>>1) ^ (key[2] & 15)) | (key[2] & 240));

		for(i=2;i<=9;i++)
		{
			subkey[round+1][i-2] = key[i];
		}

		round++;
	}
	while(round<31);
	
//	****************** End Key Scheduling ******************
	do	{
//	****************** addRoundkey *************************
		i=0;
		do
		{
			message[i] = message[i] ^ subkey[round][i];
			temp_pLayer[i] = 0;
			i++;
		}
		while(i<=7);
//	****************** End addRoundkey *********************
//	****************** pLayer ******************************
		for(i=0;i<64;i++)
		{
			position = (4*i) % 63;						//arthmetic calculation of the pLayer
			if(i == 63)									//Exception for bit 63
				position = 63;
			element_source = i / 8;
			bit_source = i % 8;
			element_destination = position / 8;
			bit_destination = position % 8;
			temp_pLayer[element_destination] |= ((message[element_source]>>bit_source) & 0x1) << bit_destination;
		}
		for(i=0;i<=7;i++)
		{
			message[i] = temp_pLayer[i];
		}
//	****************** End pLayer **************************
//	****************** sBox ********************************
		i=0;
		do
		{
			message[i] = invsBox4[message[i]>>4]<<4 | invsBox4[message[i] & 0xF];
			i++;
		}
		while(i<=7);
//	****************** End sBox ****************************
		round--;
	}
	while(round>0);
//	****************** addRoundkey *************************
	i = 0;
	do												//final key XOR
	{
		message[i] = message[i] ^ subkey[0][i];
		i++;
	}
	while(i<=7);


	for ( i = 0 ; i < 8 ; i++ ) {
      printf( "%02X ", message[8 - 1 - i] );
    }
    printf( "\n" );	

	
//	****************** End addRoundkey *********************
//	****************** End Encryption **********************
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

int main(int argc, char** argv)
{
	parse_opts(argc, argv);

    if ( loadkey( myKey ) != true ) {
      return 2;
    }
    printf("Encryption Key: 	");
   	printKey();

   	if ( loadMessage( myMessage ) != true ) {
      return 3;
   	}
   	printf("Ciphertext is: 		");
   	printMessage();
   	printf("Decrypted message is: 	");
   	decrypt();
	printf("\n");
	return 0;
}

