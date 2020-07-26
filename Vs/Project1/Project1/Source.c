#include "Source.h"
#include <string.h>
#include <stdio.h>
#include "./mbedtls/platform.h"
#include "./mbedtls/aes.h"

void bin_file_encryption()
{
	char buf[16] = { 0 };
	char temp_buf[16] = { 0 };
	int ret = 0;
	FILE* read_fp = fopen("C:\\Users\\Administrator\\Desktop\\bin\\one.txt", "rb");
	if (read_fp == NULL)
	{
		printf("open file fail\n");
	}

	FILE* write_fp = fopen("C:\\Users\\Administrator\\Desktop\\bin\\enc.txt", "wb");
	if (write_fp == NULL)
	{
		printf("open file fail\n");
	}

	while (1)
	{
		int length = fread(buf, 1, 16, read_fp);
		if (length == 0)
		{
			break;
		}
		printf("encryption: %s\n", buf);
		//fwrite(buf, 1, length, write_fp);

		ret = encryption_data(buf, temp_buf, "123");
		if (ret == 0)
		{
			fwrite(temp_buf, 1, length, write_fp);
		}
		else
		{
			break;	// encryption fail
		}

		memset(buf, 0, sizeof(buf));
	}

	fclose(read_fp);
	fclose(write_fp);
}


void dacoda_file()
{
	char buf[16] = { 0 };
	char temp_buf[16] = { 0 };
	int ret = 0;
	FILE* read_fp = fopen("C:\\Users\\Administrator\\Desktop\\bin\\enc.txt", "rb");
	if (read_fp == NULL)
	{
		printf("open file fail\n");
	}

	FILE* write_fp = fopen("C:\\Users\\Administrator\\Desktop\\bin\\doc.txt", "wb");
	if (write_fp == NULL)
	{
		printf("open file fail\n");
	}

	while (1)
	{
		int length = fread(buf, 1, 16, read_fp);
		if (length == 0)
		{
			break;
		}
		printf("dacode: %s\n", buf);

		ret = decode_data(buf, temp_buf, "123");
		if (ret == 0)
		{
			fwrite(temp_buf, 1, length, write_fp);
		}
		else
		{
			break;	// dacoda fail
		}

		memset(buf, 0, sizeof(buf));
	}

	fclose(read_fp);
	fclose(write_fp);
}

int encryption_data(char data[16], char output[16], char key[32])
{
	mbedtls_aes_context ctx;
	int ret = 0;

	int keybits = 256;

	char buf[16] = { 0 };

	mbedtls_aes_init(&ctx);

	ret = mbedtls_aes_setkey_enc(&ctx, key, keybits);   //swtich to encryption
	if (ret != 0)
	{
		printf("swtich encryption fail\n");
		return 1;
	}

	ret = mbedtls_aes_crypt_ecb(&ctx, 1, data, buf);
	if (ret != 0)
	{
		printf("encryption fail\n");
		return 2;
	}

	if (ret == 0)
	{
		memcpy(output, buf, sizeof(buf));
		decode_data(buf, buf, key);
	}
	else
	{
		printf("encryption error\n");
	}

	return ret;
}

int decode_data(char data[16], char output[16], char key[32])
{
	mbedtls_aes_context ctx;

	int ret = 0;

	int keybits = 256;

	char buf[16] = { 0 };

	mbedtls_aes_init(&ctx);

	ret = mbedtls_aes_setkey_dec(&ctx, key, keybits);   //swtich to decode
	if (ret != 0)
	{
		printf("swtich decode fail\n");
		return 1;
	}
	ret = mbedtls_aes_crypt_ecb(&ctx, 0, data, buf);
	if (ret != 0)
	{
		printf("decode fail\n");
		return 2;
	}

	memcpy(output, buf, sizeof(buf));
	printf("dac:===== %s\n", buf);

	return ret;
}


int entryption_and_decode(char input[16], char* output, char key[32], uint8_t mode)
{
	mbedtls_aes_context ctx;
	int ret = 0;

	int keybits = 256;

	char buf[16] = { 0 };

	mbedtls_aes_init(&ctx);

	if (mode == 1)
	{
		ret = mbedtls_aes_setkey_enc(&ctx, key, keybits);   //swtich to encryption
	}
	else if (mode == 0)
	{
		ret = mbedtls_aes_setkey_dec(&ctx, key, keybits);   //swtich to decode
	}
	if (ret != 0)
	{
		printf("swtich encryption fail\n");
		return 1;
	}

	ret = mbedtls_aes_crypt_ecb(&ctx, mode, input, buf);
	if (ret != 0)
	{
		printf("encryption fail\n");
		return 2;
	}

	memcpy(output, buf, 16);
	return ret;
}

#if 0
int mbedtls_aes_self_test(int verbose)
{
	int ret = 0, i, j, u, mode;
	unsigned int keybits;
	unsigned char key[32];
	unsigned char buf[64];
	const unsigned char *aes_tests;

	mbedtls_aes_context ctx;
	memset(key, 0, 32);
	mbedtls_aes_init(&ctx);

	/*
	* ECB mode
	*/
	for (i = 0; i < 6; i++)
	{
		u = i >> 1;
		keybits = 128 + u * 64;
		mode = i & 1;

		if (verbose != 0)
			mbedtls_printf("  AES-ECB-%3u (%s): ", keybits,
			(mode == MBEDTLS_AES_DECRYPT) ? "dec" : "enc");

		memset(buf, 0, 16);

		if (mode == MBEDTLS_AES_DECRYPT)
		{
			ret = mbedtls_aes_setkey_dec(&ctx, key, keybits);
			aes_tests = aes_test_ecb_dec[u];
		}
		else
		{
			ret = mbedtls_aes_setkey_enc(&ctx, key, keybits);
			aes_tests = aes_test_ecb_enc[u];
		}

		/*
		* AES-192 is an optional feature that may be unavailable when
		* there is an alternative underlying implementation i.e. when
		* MBEDTLS_AES_ALT is defined.
		*/
		if (ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED && keybits == 192)
		{
			mbedtls_printf("skipped\n");
			continue;
		}
		else if (ret != 0)
		{
			goto exit;
		}

		for (j = 0; j < 10000; j++)
		{
			ret = mbedtls_aes_crypt_ecb(&ctx, mode, buf, buf);
			if (ret != 0)
				goto exit;
		}

		if (memcmp(buf, aes_tests, 16) != 0)
		{
			ret = 1;
			goto exit;
		}

		if (verbose != 0)
			mbedtls_printf("passed\n");
	}

	if (verbose != 0)
		mbedtls_printf("\n");
exit:
	return ret;
}
#endif

