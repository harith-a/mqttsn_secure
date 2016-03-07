#include "presentcbc.h"
#include "pcg_basic.h"

uint8_t theKey[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
uint8_t iv[] =  {0x0f,0x79,0xc1,0x38,0x7b,0x22,0x84,0x45};
char *str,*key,*initv;
char *mystr = "sayaaaaaaaasdadad";

unsigned long lenstr, lenmsg; 
int blok,baki,pad;
int rounds = 5;

void printMessage( uint8_t *msg, size_t saiz  ) {
   uint8_t i;

   for ( i = 0 ; i < saiz ; i++ ) {
      printf( "%02X ", msg[saiz - 1 - i] );
   }
   printf( "\n" );
}

static void usage()
{
    fprintf(stderr, "Usage: ./test [opts] -k <theKey> -m <theMessage>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -k <the Key> \n");
    fprintf(stderr, "  -m <the Message> \n");
    fprintf(stderr, "  -v <the Initialization vector>\n" );
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "./test -k \"00 00 00 00 00 00 00 00 00 00\" -v \"00 00 00 00 00 00 00 00\" -m labinisecure\n");
    exit(-1);
}

void parse_opts(int argc, char** argv)
{
    int ch;

    // Parse the options/switches
    while ((ch = getopt(argc, argv, "v:k:m:?")) != -1)
        switch (ch) {
        case 'k':
            key = optarg;
            loadkey( key );
        break;

        case 'm':
            str = optarg;
        break;

        case 'v':
            initv = optarg;
            loadMessage(initv);
        break;


        case '?':
        default:
            usage();
        break;
    }
 }

 bool loadkey( const char * parametr ) 
 {
   if ( 
        KEY_SIZE != sscanf( parametr, "%hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx",
            &theKey[9],
            &theKey[8], 
            &theKey[7], 
            &theKey[6], 
            &theKey[5], 
            &theKey[4], 
            &theKey[3], 
            &theKey[2], 
            &theKey[1], 
            &theKey[0] 
            ) 
      ) {
      printf( "loadkey(): input error!\n" );
      return false;
   }
   printf("Key loaded\n");
   return true;
}

bool loadMessage( const char * parametr ) 
{
   if ( 
        BLOCK_SIZE != sscanf( parametr, "%hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx",
            &iv[7],
            &iv[6],
            &iv[5],
            &iv[4],
            &iv[3],
            &iv[2],
            &iv[1],
            &iv[0]
            ) 
      ) {
      printf( "loadMessage(): input error!\n" );
      return false;
   }
   return true;
}

void padStr(char* str, uint8_t *padded)
{
    lenstr = strlen(str);

       
        /*pad the message to multiple of 8 bytes*/
    
        int blok = lenstr / BLOCK_SIZE;
        int baki = lenstr % BLOCK_SIZE;

        if (baki<=7)
            {   
            blok ++;
            pad = (BLOCK_SIZE - baki); 
            }
        else
            {   
            printf("Padding Error\n");   
            }
    
        uint8_t newMessage[blok * BLOCK_SIZE * sizeof(uint8_t)];
        memset(newMessage+lenstr,pad,pad);
        memcpy(newMessage,str,lenstr);
        lenmsg = sizeof(newMessage);
        memcpy(padded,newMessage,lenmsg);

}

void presentencrypt(char *str, uint8_t *retstr)
{

    pcg32_random_t rng;
    pcg32_srandom_r(&rng, time(NULL) ^ (intptr_t)&printf, (intptr_t)&rounds);
    uint32_t rang = pcg32_random_r(&rng);
    memcpy(iv,&rang,sizeof(iv));

    uint8_t newMessage[200];
    //pad the message string and turn into bytearray
    padStr(str,newMessage);

    cbc_encrypt((uint8_t*)theKey,iv,newMessage,lenmsg);

    memcpy(retstr,newMessage,sizeof(newMessage));

    printf("sizeof(newMessage) %d\n", sizeof(newMessage));
}  

// int main(int argc, char *argv[])
// {
//     if ( argc <= 1 )
//         usage();
    

//     parse_opts(argc,argv);
    
//     if (str == NULL)
//         usage();
     
//     printf("\n\n");
    
//     pcg32_random_t rng;
//     pcg32_srandom_r(&rng, time(NULL) ^ (intptr_t)&printf, (intptr_t)&rounds);

//     uint32_t rang = pcg32_random_r(&rng);
//     memcpy(iv,&rang,sizeof(iv));

//     uint8_t newMessage[200];
//     //pad the message string and turn into bytearray
//     padStr(str,newMessage);

//     printf("Initialization Vector: \n");
//     printMessage(iv,sizeof(iv));

//     printf("Plaintext: %s\n",str );
    
//     printf("\nPadded Plaintext: \n" );
//     printMessage(newMessage,lenmsg);
//     cbc_encrypt((uint8_t*)theKey,iv,newMessage,lenmsg);

//     printf("\nEncrypted Ciphertext: \n");
//     printMessage(newMessage,lenmsg);

//     cbc_decrypt((uint8_t*)theKey,iv,newMessage,lenmsg);

//     printf("\nDecrypted Plaintext: \n");
//     printMessage(newMessage,lenmsg);

//     //copy to new array with size + 1
//     pad = (int)newMessage[lenmsg-1];
//     uint8_t finMessage[lenmsg-pad+1];
//     memcpy (finMessage,newMessage,lenmsg-pad);

//     //new array without padding
//     printf("\nRemoved Padding: \n");
//     printMessage(finMessage,sizeof(finMessage)-1);

//     //add NULL pointer to turn it into string
//     memset (finMessage+lenmsg-pad,'\0',1);
//     printf("\nFinal String: %s\n",(char *)finMessage);

//     return 0;

// }



int main(int argc, char const *argv[])
{
    parse_opts(argc,argv);

    uint8_t theMessage[200];
    presentencrypt(str,theMessage);
    printf("Hai %s\n",str );
    printMessage(theMessage,lenmsg+8);
    printf("lenmsg length: %lu\n",lenmsg);
    cbc_decrypt((uint8_t*)theKey,iv,theMessage,lenmsg);
    printMessage(theMessage,lenmsg+8);

    char buf[lenmsg+1];
    int c = snprintf(buf, lenmsg+1, "%lu", theMessage);
    
    printf("%s\n",buf );
    return 0;
}



