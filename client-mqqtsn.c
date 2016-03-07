#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h> // for Linux
//#include <malloc/malloc.h> // for OSX
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <unistd.h>

#define FAIL    -1
 
int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;
 
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
 
SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = SSLv3_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}
 
int main(int count, char *strings[])
{   
    FILE * fp;   
    clock_t begin, end;
    double time_spent;

    SSL_CTX *ctx;
    int server,i=0;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char *hostname, *portnum;

while (i<86400) 
{
    begin = clock(); //start time measurement - harith
    
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];
 
    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {   char *msg = "Hello???";
 
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[bytes] = 0;
        printf("Received: \"%s\"\n\n", buf);
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    
    end = clock(); // stop time measurement -- harith
    time_spent = (double)(end - begin) / CLOCKS_PER_SEC * 1000;
      //printf("Total execution time is: %f \n", time_spent);
      //reset time
      	begin = 0;
	end   = 0; 
      
	fp = fopen( "logfile.txt", "a" ); // Open file for writing

    fprintf(fp, "Sequence %d, Time taken: %f ms \r\n",i,time_spent);

    fclose(fp);
    i++;
    sleep(1);
}
    return 0;
}
