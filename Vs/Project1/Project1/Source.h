
#ifndef __TEST_HENAD_
#define __TEST_HENAD_

#include <stdint.h>

static const unsigned char aes_test_ecb_dec[3][16] =
{
	{ 0x44, 0x41, 0x6A, 0xC2, 0xD1, 0xF5, 0x3C, 0x58,
	0x33, 0x03, 0x91, 0x7E, 0x6B, 0xE9, 0xEB, 0xE0 },
	{ 0x48, 0xE3, 0x1E, 0x9E, 0x25, 0x67, 0x18, 0xF2,
	0x92, 0x29, 0x31, 0x9C, 0x19, 0xF1, 0x5B, 0xA4 },
	{ 0x05, 0x8C, 0xCF, 0xFD, 0xBB, 0xCB, 0x38, 0x2D,
	0x1F, 0x6F, 0x56, 0x58, 0x5D, 0x8A, 0x4A, 0xDE }
};

static const unsigned char aes_test_ecb_enc[3][16] =
{
	{ 0xC3, 0x4C, 0x05, 0x2C, 0xC0, 0xDA, 0x8D, 0x73,
	0x45, 0x1A, 0xFE, 0x5F, 0x03, 0xBE, 0x29, 0x7F },
	{ 0xF3, 0xF6, 0x75, 0x2A, 0xE8, 0xD7, 0x83, 0x11,
	0x38, 0xF0, 0x41, 0x56, 0x06, 0x31, 0xB1, 0x14 },
	{ 0x8B, 0x79, 0xEE, 0xCC, 0x93, 0xA0, 0xEE, 0x5D,
	0xFF, 0x30, 0xB4, 0xEA, 0x21, 0x63, 0x6D, 0xA4 }
};


int mbedtls_aes_check(const char input[16], char output[16], char key[32], uint8_t mode, uint8_t verbose);

int encryption_data(char data[16], char output[16], char key[32]);

int decode_data(char data[16], char output[16], char key[32]);

int entryption_and_decode(char input[16], char output[16], char key[32], uint8_t mode);

void bin_file_encryption();

void dacoda_file();

#endif
