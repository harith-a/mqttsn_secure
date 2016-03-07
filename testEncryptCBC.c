#include "presentcbc.h"


uint8_t theKey[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
uint8_t iv[] =  {0x0f,0x79,0xc1,0x38,0x7b,0x22,0x84,0x45};
char *str,*key,*initv;
// char* key;
// char* initv;
unsigned long lenstr, lenmsg; 
int blok,baki,pad;

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

 bool loadkey( const char * parametr ) {
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

bool loadMessage( const char * parametr ) {
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

/* Test present.c function - deprecated because I 
changed above functions */

// int main(int argc, char** argv)
// {

//     printf("PlainText: " );
//     printCMessage(theMessage);

//     printf("\nEncryption Key: ");
//     printKey(theKey);

//     encryptP(theCipher,theMessage,theKey);

//     printf("\nEncrypted Ciphertext: ");
//     printMessage(theCipher);

//     decryptP(theDecrypt,theCipher,theKey);
//     printf("\nDecrypted text: ");
//     printMessage(theDecrypt);

// }

/* test CBC function */

// int main(int argc, char const *argv[])
// {
//     printf("PlainText: \n" );
//     printMessage(theMessage16,sizeof(theMessage16));
//     cbc_encrypt(theKey,iv,theMessage16,sizeof(theMessage16));

//     printf("\nEncrypted Ciphertext: \n");
//     printMessage(theMessage16,sizeof(theMessage16));

//     cbc_decrypt(theKey,iv,theMessage16,sizeof(theMessage16));

//     printf("\nDecrypted Plaintext: \n");
//     printMessage(theMessage16,sizeof(theMessage16));
// }


int main(int argc, char *argv[])
{
    if ( argc <= 1 )
        usage();
    
    parse_opts(argc,argv);
    
    if (str == NULL)
        usage();
     
    printf("\n\n");
    lenstr = strlen(str);
    // printf("%lu\n", lenstr);
       
        /*pad the message to multiple of 8 bytes*/
    
        blok = lenstr / BLOCK_SIZE;
        baki = lenstr % BLOCK_SIZE;

        if (baki<=7)
            {   
            blok ++;
            pad = (BLOCK_SIZE - baki); 
            }
        else
            {   
            printf("Padding Error\n");
                return 1;   
            }
    
        uint8_t newMessage[blok * BLOCK_SIZE * sizeof(uint8_t)];
        memset(newMessage+lenstr,pad,pad);
        memcpy(newMessage,str, lenstr);
        lenmsg = sizeof(newMessage);
        /*padding ends*/

    printf("Plaintext: %s\n",str );
    
    printf("\nPadded Plaintext: \n" );
    printMessage(newMessage,lenmsg);
    cbc_encrypt((uint8_t*)theKey,iv,newMessage,lenmsg);

    printf("\nEncrypted Ciphertext: \n");
    printMessage(newMessage,lenmsg);

    cbc_decrypt((uint8_t*)theKey,iv,newMessage,lenmsg);

    printf("\nDecrypted Plaintext: \n");
    printMessage(newMessage,lenmsg);

    //copy to new array with size + 1
    pad = (int)newMessage[lenmsg-1];
    uint8_t finMessage[lenmsg-pad+1];
    memcpy (finMessage,newMessage,lenmsg-pad);

    //new array without padding
    printf("\nRemoved Padding: \n");
    printMessage(finMessage,sizeof(finMessage)-1);

    //add NULL pointer to turn it into string
    memset (finMessage+lenmsg-pad,'\0',1);
    printf("\nFinal String: %s\n",(char *)finMessage);

    return 0;

}







