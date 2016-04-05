#define INLINE

#include <stdint.h>
#include <string.h>
typedef int8_t s8;
typedef uint8_t u8;
typedef uint16_t u16;

#define BLOCK_SIZE	8

static const u8 sBox[16] =
{0x7, 0x4, 0xa, 0x9, 0x1, 0xf, 0xb, 0x0,
0xc, 0x3, 0x2, 0x6, 0x8, 0xe, 0xd, 0x5};

void KeySetup ( u8 k[], u8 r );
void InvKeySetup ( u8 k[], u8 r );
void KLEINEncrypt ( u8 text[], u8 crypt[], u8 key[] );
void KLEINDecrypt ( u8 text[], u8 crypt[], u8 key[] );
void klein_cbc_encrypt( uint8_t *key, const uint8_t *iv, uint8_t *data, size_t data_len);
void klein_cbc_decrypt( uint8_t *key, const uint8_t *iv, uint8_t *data, size_t data_len);