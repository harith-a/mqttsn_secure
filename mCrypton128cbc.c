// #define PRINT

//#define KSIZE 64 
//#define KSIZE 96


// #ifdef PRINT
//#include "tools.h"
// #endif

/**********************************************************************/
/**********************************************************************/
void EncryptKeySchedule(const u16 *mkey, u16 rkey[NBROUND+1][KSIZE>>4])
{
	u16 i,U[KSIZE>>4],temp,temp1,temp2;
	for(i=0;i<(KSIZE>>4);i++) U[i]=mkey[i];
	for(i=0;i<NBROUND+1;i++)
	{
		 temp=( sBox[0][((U[0]>>12)&0xF)] ^ KSCte[i])&0xF;
		 rkey[i][0]=U[1]^(temp<<12);		 
		 temp=( sBox[1][((U[0]>>8)&0xF)]  ^ KSCte[i] )&0xF;	
		 rkey[i][1]=U[2]^(temp<<8);	
		 temp=( sBox[2][(U[0]>>4)&0xF]   ^KSCte[i])&0xF;
		 rkey[i][2]=U[3]^(temp<<4);
		 temp=( sBox[3][U[0]&0xF]       ^ KSCte[i])&0xF;

#if KSIZE == 64
		 rkey[i][3]=U[0]^temp;
		 
		 temp=U[0];
		 U[0]=U[1];
		 U[1]=U[2];
		 U[2]=U[3];
		 U[3]=(temp<<3)^(temp>>13);
		 
#elif KSIZE == 96
		 rkey[i][3]=U[4]^temp;
		 
		 temp=U[5];
		 U[5]=U[4];
		 U[4]=(U[3]<<8)^(U[3]>>8);
		 U[3]=U[2];
		 U[2]=U[1];
		 U[1]=(U[0]<<3)^(U[0]>>13);
		 U[0]=temp;
		 
#elif KSIZE == 128
		 rkey[i][3]=U[4]^temp;
		 
		 temp = U[0];
		 U[0] = U[5];
		 U[5] = U[2];
		 temp2 = U[3];
		 U[3] = (temp<<3)^(temp>>13);
		 temp = U[1];
		 U[1] = U[6];
		 U[6] = temp2;
		 temp1 = U[4];
		 U[4] = temp;
		 temp = U[2];
		 U[2] = U[7];
		 U[7] = (temp1<<8)^(temp1>>8);
		 
#endif
	}
	return;
}

void DecryptKeySchedule(const u16 *mkey, u16 rkey[NBROUND+1][KSIZE>>4])
{
	u16 i,V[KSIZE>>4],temp;
	
#if KSIZE == 64
	for(i=0;i<(KSIZE>>4);i++) V[i]=(mkey[i]<<9)^(mkey[i]>>7);
#elif KSIZE == 96
	for(i=0;i<(KSIZE>>4);i++) V[i]=(mkey[i]<<6)^(mkey[i]>>10);
#elif KSIZE == 128
	V[0]=(mkey[4]<<3)^(mkey[4]>>13);
	V[1]=(mkey[5]<<14)^(mkey[5]>>2);
	V[2]=(mkey[6]<<3)^(mkey[6]>>13);
	V[3]=(mkey[7]<<14)^(mkey[7]>>2);
	V[4]=(mkey[0]<<14)^(mkey[0]>>2);
	V[5]=(mkey[1]<<3)^(mkey[1]>>13);
	V[6]=(mkey[2]<<14)^(mkey[2]>>2);
	V[7]=(mkey[3]<<3)^(mkey[3]>>13);
#endif

	for(i=0;i<NBROUND+1;i++)
	{
		 temp=( sBox[0][(V[0]>>12)&0xF] ^ KSCte[12-i])&0xF;
		 rkey[i][0]=Phi_Key(0,V[1]^(temp<<12));
		 
		 temp=( sBox[1][(V[0]>>8)&0xF]  ^ KSCte[12-i])&0xF;
		 rkey[i][1]=Phi_Key(1,V[2]^(temp<<8));
		 
		 temp=( sBox[2][(V[0]>>4)&0xF]  ^ KSCte[12-i])&0xF;
		 rkey[i][2]=Phi_Key(2,V[3]^(temp<<4));
		 
		 temp=( sBox[3][V[0]&0xF]       ^ KSCte[12-i])&0xF;

#if KSIZE == 64
		 rkey[i][3]=Phi_Key(3,V[0]^temp);
		 
		 temp=V[3];
		 V[3]=V[2];
		 V[2]=V[1];
		 V[1]=V[0];
		 V[0]=(temp<<13)^(temp>>3);
		 
#elif KSIZE == 96
		 rkey[i][3]=Phi_Key(3,V[4]^temp);
		 
		 temp=V[0];
		 V[0]=(V[1]<<13)^(V[1]>>3);
		 V[1]=V[2];
		 V[2]=V[3];
		 V[3]=(V[4]<<8)^(V[4]>>8);
		 V[4]=V[5];
		 V[5]=temp;
		 
#elif KSIZE == 128
		 rkey[i][3]=Phi_Key(3,V[4]^temp);
		 
		 u16 temp1,temp2;
		 temp=V[0];
		 temp1=V[1];
		 temp2=V[2];
		 V[0]=(V[3]<<13)^(V[3]>>3);
		 V[1]=V[4];
		 V[2]=V[5];
		 V[3]=V[6];
		 V[4]=(V[7]<<8)^(V[7]>>8);
		 V[5]=temp;
		 V[6]=temp1;
		 V[7]=temp2;
#endif
	}
	return;
}
/**********************************************************************/
/**********************************************************************/
u16 Phi_Key(u8 ind,u16 value)
{
	u8 j,k;
	u16 temp,result=0;
	for(j=0;j<4;j++)
	{
		temp=0;
		for(k=0;k<4;k++)
		{
			temp^= Mask[((ind+j+k)&0x03)] & ((value>>(12-4*k))&0xF);
		}
		result^=temp<<(12-4*j);
	}
	return result;
}


void Gamma_SBox(u8 state[4][4])
{
	u8 i,j;
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			state[i][j]=sBox[((i+j)&0x3)][state[i][j]];
		}
	}
	return;
}

void Gamma_SBox_Inv(u8 state[4][4])
{
	u8 i,j;
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			state[i][j]=sBox[((i+j+2)&0x03)][state[i][j]];
		}
	}
	return;
}


void Pi_Permut(u8 state[4][4])
{
	u8 i,j,k;
	u8 temp[4];
	
    for(i=0;i<4;i++)
	{        
		for(j=0;j<4;j++)
		{
			temp[j]=0;
			for(k=0;k<4;k++)
			{
				temp[j]^= Mask[((i+j+k)&0x03)] & state[k][i];
			}
		}
		state[0][i]=temp[0];
		state[1][i]=temp[1];
		state[2][i]=temp[2];
		state[3][i]=temp[3];
	}
	return;
}

void Tau_Transp(u8 state[4][4])
{
	u16 i,j,temp;
	for(i=0;i<3;i++)
	{
		for(j=1+i;j<4;j++)
		{
			temp=state[i][j];
			state[i][j]=state[j][i];
			state[j][i]=temp;
		}
	}
	return;
}
void Sigma_KeyAdd(u8 state[4][4], const u16 *rkey)
{
	u16 i,j,tempkey;
	for(i=0;i<4;i++)
	{
		tempkey=rkey[i];
		for(j=0;j<4;j++)
		{
			state[i][3-j] ^= tempkey&0x000F;
			tempkey>>=4;
		}
	}
	return;
}

void mCEncrypt(u8 state[4][4],u16 rkey[NBROUND+1][KSIZE>>4])
{
	 u8 k;
	 
	 Sigma_KeyAdd(state, rkey[0]);
	 
     for(k=0; k<NBROUND;k++)
     {
		 Gamma_SBox(state);
		 Pi_Permut(state);
		 Tau_Transp(state);
		 Sigma_KeyAdd(state, rkey[k+1]);
     }
     Tau_Transp(state);
	 Pi_Permut(state);
	 Tau_Transp(state); 

	 return;
}

void mCDecrypt(u8 state[4][4],u16 dkey[NBROUND+1][KSIZE>>4])
{
   	 u8 i,j,k;
   	 u16 tempkey;
	 
	 Sigma_KeyAdd(state, dkey[0]); 
     for(k=0; k<NBROUND;k++)
     {
		 Gamma_SBox_Inv(state);
		 Pi_Permut(state);
    	 Tau_Transp(state);
    	 Sigma_KeyAdd(state, dkey[k+1]);    	
     } 
     Tau_Transp(state);
	 Pi_Permut(state);
	 Tau_Transp(state); 
    
	 return;

}

void mCrypton_cbc_encrypt( uint16_t *key, const uint8_t *iv, uint8_t *data, size_t data_len)
{
        uint8_t cbc[BLOCK_SIZE];
        uint8_t *pos = data;
        int i, j, blocks;

        memcpy(cbc,iv,BLOCK_SIZE);

        blocks = data_len / BLOCK_SIZE;

        u16 rkey[NBROUND+1][KSIZE>>4],key[KSIZE>>4];
        EncryptKeySchedule(key,rkey);
        
        for (i = 0; i < blocks; i++) {
                for (j = 0; j < BLOCK_SIZE; j++)
                        cbc[j] ^= pos[j];
                mCEncrypt(cbc,key);
                memcpy(pos, cbc, BLOCK_SIZE);
                pos += BLOCK_SIZE;
        }
}

void mCrypton_cbc_decrypt( uint8_t *key, const uint8_t *iv, uint8_t *data, size_t data_len)
{
        uint8_t cbc[BLOCK_SIZE], tmp[BLOCK_SIZE];
        uint8_t *pos = data;
        int i, j, blocks;

        memcpy(cbc, iv, BLOCK_SIZE);

        blocks = data_len / BLOCK_SIZE;
        for (i = 0; i < blocks; i++) {
                memcpy(tmp, pos, BLOCK_SIZE);
                KLEINDecrypt ( pos, pos, key ); 
                for (j = 0; j < BLOCK_SIZE; j++)
                        pos[j] ^= cbc[j];
                memcpy(cbc, tmp, BLOCK_SIZE);
                pos += BLOCK_SIZE;
        }
}



/**********************************************************************/
/**********************************************************************/
/*
int main()
{
#ifdef PRINT
//uart1_init();
u16 i,j;
#endif

	u16 rkey[NBROUND+1][KSIZE>>4],mkey[KSIZE>>4];
	u16 dkey[NBROUND+1][KSIZE>>4];
  
    mkey[0] = 0x0001;
    mkey[1] = 0x0203; 
    mkey[2] = 0x0405;
    mkey[3] = 0x0607;
    mkey[4] = 0x0809;
    mkey[5] = 0x0a0b;
    mkey[6] = 0x0c0d; 
    mkey[7] = 0x0e0f;
        
    
   u8 state[4][4]={{0,0,0,1},{0,2,0,3},{0,4,0,5},{0,6,0,7}};

#ifdef PRINT
printf("----------Plaintext----------\n\n");
for(i=0;i<4;i++)
{
for(j=0;j<4;j++)
{
printf("%X",state[i][j]);} } printf("\n");

printf("----------Encrypted----------\n\n");
#endif		

	// START_ENCRYPT();
	EncryptKeySchedule(mkey,rkey);
	Encrypt(state,rkey);
	
#ifdef PRINT
for(i=0;i<4;i++)
{
for(j=0;j<4;j++)
{
printf("%X",state[i][j]);} } printf("\n");


printf("----------Decrypted----------\n\n");
#endif

//	START_DECRYPT();
	DecryptKeySchedule(mkey,dkey);    
	Decrypt(state,dkey);
//	END_EXPE();
	
#ifdef PRINT
for(i=0;i<4;i++)
{
for(j=0;j<4;j++)
{
printf("%X",state[i][j]);} } printf("\n");


#endif

	return 0;
}

*/
