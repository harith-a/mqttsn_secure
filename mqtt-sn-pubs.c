/*
  MQTT-SN command-line publishing client
  Copyright (C) 2013 Nicholas Humfrey

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include "mqtt-sn.h"
#include "presentcbc.h"
#include "present/pcg_basic.h"

#include "aes/aes.h"

//aes
uint8_t aeskey[16] =        { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
    // 512bit text
uint8_t plain_text[64] = { (uint8_t) 0x6b, (uint8_t) 0xc1, (uint8_t) 0xbe, (uint8_t) 0xe2, (uint8_t) 0x2e, (uint8_t) 0x40, (uint8_t) 0x9f, (uint8_t) 0x96, (uint8_t) 0xe9, (uint8_t) 0x3d, (uint8_t) 0x7e, (uint8_t) 0x11, (uint8_t) 0x73, (uint8_t) 0x93, (uint8_t) 0x17, (uint8_t) 0x2a,
                           (uint8_t) 0xae, (uint8_t) 0x2d, (uint8_t) 0x8a, (uint8_t) 0x57, (uint8_t) 0x1e, (uint8_t) 0x03, (uint8_t) 0xac, (uint8_t) 0x9c, (uint8_t) 0x9e, (uint8_t) 0xb7, (uint8_t) 0x6f, (uint8_t) 0xac, (uint8_t) 0x45, (uint8_t) 0xaf, (uint8_t) 0x8e, (uint8_t) 0x51,
                           (uint8_t) 0x30, (uint8_t) 0xc8, (uint8_t) 0x1c, (uint8_t) 0x46, (uint8_t) 0xa3, (uint8_t) 0x5c, (uint8_t) 0xe4, (uint8_t) 0x11, (uint8_t) 0xe5, (uint8_t) 0xfb, (uint8_t) 0xc1, (uint8_t) 0x19, (uint8_t) 0x1a, (uint8_t) 0x0a, (uint8_t) 0x52, (uint8_t) 0xef,
                           (uint8_t) 0xf6, (uint8_t) 0x9f, (uint8_t) 0x24, (uint8_t) 0x45, (uint8_t) 0xdf, (uint8_t) 0x4f, (uint8_t) 0x9b, (uint8_t) 0x17, (uint8_t) 0xad, (uint8_t) 0x2b, (uint8_t) 0x41, (uint8_t) 0x7b, (uint8_t) 0xe6, (uint8_t) 0x6c, (uint8_t) 0x37, (uint8_t) 0x10 };



//present
uint8_t theKey[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
uint8_t iv[] =  {0x0f,0x79,0xc1,0x38,0x7b,0x22,0x84,0x45};
char *str;

int lenstr, lenmsg; 
int blok,baki,pad;
int rounds = 5;

const char *client_id = NULL;
const char *topic_name = NULL;
char *message_data = "nama";
time_t keep_alive = 30;
const char *mqtt_sn_host = "127.0.0.1";
const char *mqtt_sn_port = "1884";
uint16_t topic_id = 0;
uint8_t topic_id_type = MQTT_SN_TOPIC_TYPE_NORMAL;
int8_t qos = 0;
uint8_t retain = FALSE;
uint8_t debug = TRUE;


static void usage()
{
    fprintf(stderr, "Usage: mqtt-sn-pubs [opts] -t <topic> -m <message>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -d             Enable debug messages.\n");
    fprintf(stderr, "  -h <host>      MQTT-SN host to connect to. Defaults to '%s'.\n", mqtt_sn_host);
    fprintf(stderr, "  -i <clientid>  ID to use for this client. Defaults to 'mqtt-sn-tools-' with process id.\n");
    fprintf(stderr, "  -m <message>   Message payload to send.\n");
    fprintf(stderr, "  -n             Send a null (zero length) message.\n");
    fprintf(stderr, "  -p <port>      Network port to connect to. Defaults to %s.\n", mqtt_sn_port);
    fprintf(stderr, "  -q <qos>       Quality of Service value (0 or -1). Defaults to %d.\n", qos);
    fprintf(stderr, "  -r             Message should be retained.\n");
    fprintf(stderr, "  -t <topic>     MQTT topic name to publish to.\n");
    fprintf(stderr, "  -T <topicid>   Pre-defined MQTT-SN topic ID to publish to.\n");
    exit(-1);
}

static void parse_opts(int argc, char** argv)
{
    int ch;

    // Parse the options/switches
    while ((ch = getopt(argc, argv, "dh:i:m:np:q:rt:T:?")) != -1)
        switch (ch) {
        case 'd':
            debug = TRUE;
        break;

        case 'h':
            mqtt_sn_host = optarg;
        break;

        case 'i':
            client_id = optarg;
        break;

        case 'm':
            message_data = optarg;
        break;

        case 'n':
            message_data = "";
        break;

        case 'p':
            mqtt_sn_port = optarg;
        break;

        case 'q':
            qos = atoi(optarg);
        break;

        case 'r':
            retain = TRUE;
        break;

        case 't':
            topic_name = optarg;
        break;

        case 'T':
            topic_id = atoi(optarg);
        break;

        case '?':
        default:
            usage();
        break;
    }

    // Missing Parameter?
    if (!(topic_name || topic_id) || !message_data) {
        usage();
    }

    //if (qos != -1 && qos != 0) {
    //    fprintf(stderr, "Error: only QoS level 0 or -1 is supported.\n");
    //    exit(-1);
    //}

    // Both topic name and topic id?
    if (topic_name && topic_id) {
        fprintf(stderr, "Error: please provide either a topic id or a topic name, not both.\n");
        exit(-1);
    }

    // Check topic is valid for QoS level -1
    if (qos == -1 && topic_id == 0 && strlen(topic_name) != 2) {
        fprintf(stderr, "Error: either a pre-defined topic id or a short topic name must be given for QoS -1.\n");
        exit(-1);
    }
}

int main(int argc, char* argv[])
{
    int sock;
    int i=1;

    //Variables for time taking
    struct timeval start, end, seed;
    // FILE *fp;
    float taken;

    // Parse the command-line options
    parse_opts(argc, argv);

    // Enable debugging?
    // mqtt_sn_set_debug(debug);
  
    // Create a UDP socket
    sock = mqtt_sn_create_socket(mqtt_sn_host, mqtt_sn_port);
    if (sock) {

        
        // Connect to gateway
        if (qos >= 0) {
            mqtt_sn_send_connect(sock, client_id, keep_alive);
            mqtt_sn_receive_connack(sock);
        }

        if (topic_id) {
            // Use pre-defined topic ID
            topic_id_type = MQTT_SN_TOPIC_TYPE_PREDEFINED;
        } else if (strlen(topic_name) == 2) {
            // Convert the 2 character topic name into a 2 byte topic id
            topic_id = (topic_name[0] << 8) + topic_name[1];
            topic_id_type = MQTT_SN_TOPIC_TYPE_SHORT;
        } else if (qos >= 0) {
            // Register the topic name
            mqtt_sn_send_register(sock, topic_name);
            topic_id = mqtt_sn_receive_regack(sock);
            topic_id_type = MQTT_SN_TOPIC_TYPE_NORMAL;
        }

        // gettimeofday(&start, NULL);
        // while(i<=1000)
        // {
        gettimeofday(&start, NULL);

        uint8_t newMessage[256];
        padStr(message_data,newMessage,&lenmsg);

        printf("Plaintext\n"); 
        printMessage(message_data,lenmsg);

        gettimeofday(&seed, NULL);
        pcg32_random_t rng;
        pcg32_srandom_r(&rng, seed.tv_usec ^ (intptr_t)&printf, (intptr_t)&rounds);
        uint32_t rang = pcg32_random_r(&rng);
        memcpy(iv,&rang,sizeof(iv));


        AES128_CBC_encrypt_buffer(newMessage, message_data, lenmsg, aeskey, iv);
       
        printf("Ciphertext\n");
        printMessage(newMessage,lenmsg);


        // // Encrypt Message
        // uint8_t newMessage[200];
        // // Pad the message string and turn into bytearray, also retreive length of padded string
        // padStr(message_data,newMessage,&lenmsg);
        // // Create random IV
        // gettimeofday(&seed, NULL);
        // pcg32_random_t rng;
        // pcg32_srandom_r(&rng, seed.tv_usec ^ (intptr_t)&printf, (intptr_t)&rounds);
        // uint32_t rang = pcg32_random_r(&rng);
        // memcpy(iv,&rang,sizeof(iv));

        // // printf("\nPadded Plaintext: \n");
        // // printMessage(newMessage,lenmsg);
        // cbc_encrypt((uint8_t*)theKey,iv,newMessage,lenmsg);

        // uint8_t sendMessage[lenmsg+8]; //create array with space for iv
        // memcpy(sendMessage,iv,8);
        // memcpy(sendMessage+8,newMessage,lenmsg);
         

        // printf("\nEncrypted Ciphertext: \n");
        // printMessage(sendMessage,sizeof(sendMessage));

        uint8_t sendMessage[255];
        memcpy(&sendMessage,&newMessage,sizeof(message_data));
        // Publish to the topic 
        mqtt_sn_send_secure_publish(sock, topic_id, topic_id_type, sendMessage ,lenmsg+8, qos, retain); 
        
        // Manage Return Packets and Retrasnmits - harith
        if (qos >= 1){
        
            if (qos == 1){

                struct timeval tv;
                fd_set rfd;
                int ret;
                int resend = 0;

                while (resend < 5){

                FD_ZERO(&rfd);
                FD_SET(sock, &rfd);

                tv.tv_sec = 1;
                tv.tv_usec = 0;

                ret = select(FD_SETSIZE, &rfd, NULL, NULL, &tv);
                    if (ret < 0) {
                        printf("Select() Error!\n" );
                        exit(EXIT_FAILURE);
                    }
                    else if (ret > 0) {
                        // Receive a packet
                        mqtt_sn_receive_puback(sock);
                        resend = 6;
                    }
                    else if (ret == 0)
                    {
                        printf("republishing...\n");
                        mqtt_sn_send_secure_publish(sock, topic_id, topic_id_type, sendMessage ,lenmsg+8, qos, retain); 
                        resend++;
                    }
                }
            }

            //QOS=2
            else if(qos==2){

                struct timeval tv;
                fd_set rfd;
                int ret;
                int resendpublish = 0;
                int resendpubrel = 0;

                while (resendpublish < 5){

                FD_ZERO(&rfd);
                FD_SET(sock, &rfd);

                tv.tv_sec = 1;
                tv.tv_usec = 0;

                ret = select(FD_SETSIZE, &rfd, NULL, NULL, &tv);
                    if (ret < 0) {
                        printf("Select() Error!\n" );
                        exit(EXIT_FAILURE);
                    }
                    else if (ret > 0) {

                        // Receive a packet
                        mqtt_sn_receive_pubrec(sock);
                        resendpublish = 6; //exit loop 
                        mqtt_sn_send_pubrel(sock);
                    }
                    else if (ret == 0)
                    {
                        printf("republishing qos21...\n");
                        mqtt_sn_send_secure_publish(sock, topic_id, topic_id_type, sendMessage ,lenmsg+8, qos, retain); 
                        resendpublish++;
                    }
                }

                //retransmit pubrel
                while (resendpubrel < 5){

                FD_ZERO(&rfd);
                FD_SET(sock, &rfd);

                tv.tv_sec = 1;
                tv.tv_usec = 0;

                ret = select(FD_SETSIZE, &rfd, NULL, NULL, &tv);
                    if (ret < 0) {
                        printf("Select() Error!\n" );
                        exit(EXIT_FAILURE);
                    }
                    else if (ret > 0) {

                        // Receive a packet
                        mqtt_sn_receive_pubcomp(sock);
                        resendpubrel = 6;
                    }
                    else if (ret == 0)
                    {
                        printf("republishing qos22...\n");
                        mqtt_sn_send_pubrel(sock);
                        resendpubrel++;
                    }
                } 

            }
        }
        
        gettimeofday(&end, NULL);

        // taken = (int)((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec))/1000000;

        taken = (float)((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec))/1000;

        printf("Time taken is:%3.2f ms\n\n",taken);
        //open file for writing
        // fp = fopen( "logfile.csv", "a" ); // Open file for writing
        // fprintf(fp, "Seq %d , %3.2fms, ",i,taken);
        // fprintf(fp,"Time %s\r\n",ctime((const time_t *) &end.tv_sec));
        // fclose(fp);

        // printf("Time taken is:%3.2d s\n\n", (int)((end.tv_sec * 1000000 + end.tv_usec)
        //   - (start.tv_sec * 1000000 + start.tv_usec))/1000000);
        
        usleep(500);
        i++;
        // if(taken>=2){
        //     printf("%d messages sent.\n", i);    
        //     exit(EXIT_SUCCESS);
        // }
        
        // }

        if (qos >= 0) {
            mqtt_sn_send_disconnect(sock);
            mqtt_sn_receive_disconnect(sock);
        }

        close(sock); 
    }

    
    mqtt_sn_cleanup();
  
    return 0;
}


