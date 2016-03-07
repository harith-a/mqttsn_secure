//gcc testEncryptDecrypt.c present.c -o present.out

#include "present.h"

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

void parse_opts(int argc, char** argv)
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
    printf("Plaintext: " );
    printf("%s\n", myMessage);
    printf("Encryption Key: " );
    printf("%s\n",myKey );

    // encryptP(&myMessage,myKey);
    // printf("\nCiphertext: " );
    // printMessage(myMessage);
    

    decryptP(&myMessage,myKey);
    printf("\nDecrypted text: ");
    printMessage(myMessage);
}