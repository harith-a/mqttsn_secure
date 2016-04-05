#include "lblockcbc.h"

 void EncryptKeySchedule(u8 key[10], u8 output[NBROUND][4])
{
     u8 i, KeyR[4];
     
     output[0][3] = key[9];
     output[0][2] = key[8];
     output[0][1] = key[7];
     output[0][0] = key[6];
     
     for(i=1;i<32;i++)
     {
     // K <<< 29                 
     KeyR[3]=key[9];
     KeyR[2]=key[8];
     KeyR[1]=key[7];     
     KeyR[0]=key[6];     
     
     key[9]=(((key[6] & 0x07)<<5)&0xE0) ^ (((key[5]& 0xF8)>>3) & 0x1F);
     key[8]=(((key[5] & 0x07)<<5)&0xE0) ^ (((key[4]& 0xF8)>>3) & 0x1F);
     key[7]=(((key[4] & 0x07)<<5)&0xE0) ^ (((key[3]& 0xF8)>>3) & 0x1F);
     key[6]=(((key[3] & 0x07)<<5)&0xE0) ^ (((key[2]& 0xF8)>>3) & 0x1F);
     key[5]=(((key[2] & 0x07)<<5)&0xE0) ^ (((key[1]& 0xF8)>>3) & 0x1F);
     key[4]=(((key[1] & 0x07)<<5)&0xE0) ^ (((key[0]& 0xF8)>>3) & 0x1F);
     key[3]=(((key[0] & 0x07)<<5)&0xE0) ^ (((KeyR[3]& 0xF8)>>3) & 0x1F);
     key[2]=(((KeyR[3] & 0x07)<<5)&0xE0) ^ (((KeyR[2]& 0xF8)>>3) & 0x1F);
     key[1]=(((KeyR[2] & 0x07)<<5)&0xE0) ^ (((KeyR[1]& 0xF8)>>3) & 0x1F);
     key[0]=(((KeyR[1] & 0x07)<<5)&0xE0) ^ (((KeyR[0]& 0xF8)>>3) & 0x1F);         
                    
     // reste du keyschedule                 
     key[9]=(S9[((key[9]>>4) & 0x0F)]<<4) ^ S8[(key[9]& 0x0F)];
     
     key[6]=key[6] ^ ((i>>2) & 0x07);
     key[5]=key[5] ^ ((i & 0x03)<<6);
        
     output[i][3] = key[9];
     output[i][2] = key[8];
     output[i][1] = key[7];
     output[i][0] = key[6];                      
     }                          
}


 void OneRound(u8 x[8], u8 k[4])
{
	u8 t[4],tmp[4];
	
	tmp[0]=x[4];
	tmp[1]=x[5];
	tmp[2]=x[6];
	tmp[3]=x[7];	
	
	
	// AJOUT CLE
    x[4]=x[4]^k[0]; 
    x[5]=x[5]^k[1]; 
    x[6]=x[6]^k[2]; 
    x[7]=x[7]^k[3];         

    // PASSAGE DANS LES BOITES S
    x[4] = ((S1[((x[4])>>4) & 0x0F])<<4)^S0[(x[4] & 0x0F)];
    x[5] = ((S3[((x[5])>>4) & 0x0F])<<4)^S2[(x[5] & 0x0F)];
    x[6] = ((S5[((x[6])>>4) & 0x0F])<<4)^S4[(x[6] & 0x0F)];
    x[7] = ((S7[((x[7])>>4) & 0x0F])<<4)^S6[(x[7] & 0x0F)];            
    
    // PASSAGE DE LA PERMUTATION P
	t[0] =((x[4]>>4) & 0x0F)^(x[5] & 0xF0);
	t[1] = (x[4] & 0x0F) ^ ((x[5]& 0x0F)<<4);
	t[2] = ((x[6]>>4) & 0x0F)^(x[7] & 0xF0);
	t[3] = (x[6] & 0x0F) ^ ((x[7]& 0x0F)<<4);
    // FIN DE LA FONCTION F

    // PARTIE GAUCHE AVEC DECALAGE DE 8 SUR LA GAUCHE  
    x[4]=x[3]^t[0]; 
    x[5]=x[0]^t[1]; 
    x[6]=x[1]^t[2]; 
    x[7]=x[2]^t[3]; 
    
	// PARTIE DROITE
    x[0]=tmp[0];
    x[1]=tmp[1];
    x[2]=tmp[2];
    x[3]=tmp[3];      
    
  
}

 void LBEncrypt(u8 x[8], u8 subkey[NBROUND][4])
{
     int i;
     
     for(i=0; i<32; i++)
     {
        OneRound(x, subkey[i]);        
     }
}

 void OneRound_Inv(u8 y[8], u8 k[4])
{
     u8 t[4],tmp[4];
     
     tmp[0]=y[0];
	 tmp[1]=y[1];
	 tmp[2]=y[2];
	 tmp[3]=y[3];	
	 
	 // FAIRE PASSER Y_0, Y_1, Y_2, Y_3 dans F
	// AJOUT CLE
    y[0]=y[0]^k[0]; 
    y[1]=y[1]^k[1]; 
    y[2]=y[2]^k[2]; 
    y[3]=y[3]^k[3];  
     
 
     // PASSAGE DANS LES BOITES S
    y[0] = ((S1[((y[0])>>4) & 0x0F])<<4)^S0[(y[0] & 0x0F)];
    y[1] = ((S3[((y[1])>>4) & 0x0F])<<4)^S2[(y[1] & 0x0F)];
    y[2] = ((S5[((y[2])>>4) & 0x0F])<<4)^S4[(y[2] & 0x0F)];
    y[3] = ((S7[((y[3])>>4) & 0x0F])<<4)^S6[(y[3] & 0x0F)];    
 
   // PASSAGE DE LA PERMUTATION P
	t[0] =((y[0]>>4) & 0x0F)^(y[1] & 0xF0);
	t[1] = (y[0] & 0x0F) ^ ((y[1]& 0x0F)<<4);
	t[2] = ((y[2]>>4) & 0x0F)^(y[3] & 0xF0);
	t[3] = (y[2] & 0x0F) ^ ((y[3]& 0x0F)<<4);
    // FIN DE LA FONCTION F
    
        // PARTIE DROITE AVEC DECALAGE DE 8 SUR LA DROITE
	y[0]= y[5]^t[1]; 
    y[1]= y[6]^t[2]; 
    y[2]= y[7]^t[3]; 
    y[3]= y[4]^t[0]; 
 
 	// PARTIE GAUCHE
    y[4]=tmp[0];
    y[5]=tmp[1];
    y[6]=tmp[2];
    y[7]=tmp[3];
 
}

 void LBDecrypt(u8 x[8], u8 subkey[NBROUND][4])
{
     int i;
     
     for(i=31; i>=0; i--)
     {
        OneRound_Inv(x, subkey[i]);   
     }
}

void lblock_cbc_encrypt( uint8_t *key, const uint8_t *iv, uint8_t *data, size_t data_len)
{
        uint8_t cbc[BLOCK_SIZE];
        uint8_t *pos = data;
        int i, j, blocks;

        memcpy(cbc,iv,BLOCK_SIZE);

        blocks = data_len / BLOCK_SIZE;

        u8 rkey[NBROUND][4];
        EncryptKeySchedule(key,rkey);

        for (i = 0; i < blocks; i++) {
                for (j = 0; j < BLOCK_SIZE; j++)
                        cbc[j] ^= pos[j];
                LBEncrypt ( cbc, rkey ); 
                memcpy(pos, cbc, BLOCK_SIZE);
                pos += BLOCK_SIZE;
        }
}

void lblock_cbc_decrypt( uint8_t *key, const uint8_t *iv, uint8_t *data, size_t data_len)
{
        uint8_t cbc[BLOCK_SIZE], tmp[BLOCK_SIZE];
        uint8_t *pos = data;
        int i, j, blocks;

        memcpy(cbc, iv, BLOCK_SIZE);

        u8 rkey[NBROUND][4];
        EncryptKeySchedule(key,rkey);

        blocks = data_len / BLOCK_SIZE;
        for (i = 0; i < blocks; i++) {
                memcpy(tmp, pos, BLOCK_SIZE);
                LBDecrypt ( pos, rkey ); 
                for (j = 0; j < BLOCK_SIZE; j++)
                        pos[j] ^= cbc[j];
                memcpy(cbc, tmp, BLOCK_SIZE);
                pos += BLOCK_SIZE;
        }
}


// int main()
// {
// // #ifdef PRINT
// // uart1_init();
// // #endif
// 	u8 mkey[10];
// 	// u8 rkey[NBROUND][4];

//     mkey[0] = 0xdc;
//     mkey[1] = 0xfe; 
//     mkey[2] = 0xef;
//     mkey[3] = 0xcd;
//     mkey[4] = 0xab;
//     mkey[5] = 0x89;
//     mkey[6] = 0x67; 
//     mkey[7] = 0x45;
//     mkey[8] = 0x23; 
//     mkey[9] = 0x01;      
    
//    u8 state[16]={0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x11, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x11};
//    u8 iv[8]={0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x11}; 
// /*
// for(i=0;i<8;i++)
// {
//    state[i]=0;
//    mkey[i]=0;
// }
//    mkey[8] = 0; 
//    mkey[9] = 0;  
// */
// #ifdef PRINT
// printf("----------Clair----------\n\n");
// printf("%X %X %X %X %X %X %X %X",state[7], state[6], state[5], state[4], state[3], state[2], state[1], state[0]);
// printf("\n");
// printf("----------Chiffr\'e----------\n\n");
// #endif		
 
//  // START_ENCRYPT();
    
//  // EncryptKeySchedule(mkey,rkey);
//  lblock_cbc_encrypt(state,(u8 *)mkey,iv,sizeof(state));
 
//  #ifdef PRINT
//  printf("%X %X %X %X %X %X %X %X",state[7], state[6], state[5], state[4], state[3], state[2], state[1], state[0]);
//  printf("\n");
//  printf("----------Déchiffr\'e----------\n\n");
//  #endif

//  // START_DECRYPT();
//  lblock_cbc_decrypt(state,mkey,iv,sizeof(state));

//  #ifdef PRINT
//  printf("%X %X %X %X %X %X %X %X",state[7], state[6], state[5], state[4], state[3], state[2], state[1], state[0]);
//  printf("\n");
//  printf("----------Déchiffr\'e----------\n\n");
//  #endif

//  // END_EXPE();

// return 0;
// }

