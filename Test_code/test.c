#include "test.h"
#include <string.h>
#include <stdio.h>
#include "./mbedtls/platform.h"
#include "./mbedtls/aes.h"

int mbedtls_aes_check(const char input[16], char output[16], char key[32], uint8_t mode, uint8_t verbose)
{
    

	int ret = 0;
	unsigned int keybits;
	unsigned char buf[64];
	const unsigned char *aes_tests;



	mbedtls_aes_context ctx;
    printf("input3:%s\n", key);
	//memset( key, 0, 32 );

    
	mbedtls_aes_init( &ctx );

    printf("input2:%s\n", input);

	/*
	 * ECB mode
	 */
	keybits = 128 + 2 * 64;

	if( verbose != 0 )
		mbedtls_printf( "  AES-ECB-%3u (%s): ", keybits,
				( mode == MBEDTLS_AES_DECRYPT ) ? "dec" : "enc" );

	//memcpy(buf, input, 16);

	if( mode == MBEDTLS_AES_DECRYPT )
	{
		ret = mbedtls_aes_setkey_dec( &ctx, key, keybits );   //switch to encryption
		//aes_tests = aes_test_ecb_dec[2];
	}
	else
	{
		
		//aes_tests = aes_test_ecb_enc[2];
	}
	
	if( ret != 0 )
	{
		goto exit;
	}
    
    printf("input1:%s\n", input);
    ret = mbedtls_aes_crypt_ecb(&ctx, mode, input, buf);
    //ret = mbedtls_aes_crypt_ecb( &ctx, mode, buf, buf );
    if( ret != 0 )
        goto exit;

    if(ret == 0)
    {
        memcpy(output, buf, 16);
    }

exit:
 return ret;

}

void encryption_test(char data[16], char key[32])
{
    mbedtls_aes_context ctx;
    int ret = 0;

    int keybits = 256;

    char buf[16] = { 0 };

    mbedtls_aes_init( &ctx );

    ret = mbedtls_aes_setkey_enc( &ctx, key, keybits );   //swtich to encryption
    if(ret != 0)
    {
        printf("swtich encryption fail\n");
        return 1;
    }

    ret = bedtls_aes_crypt_ecb(&ctx, 1, data, buf);
    if(ret != 0)
    {
        printf("encryption fail\n");
        return 2;
    }

    if(ret == 0)
    {
       decode_test(buf, key); 
    }
    else
    {
        printf("encryption error\n");
    }

}

void decode_test(char data[16], char key[32])
{
    mbedtls_aes_context ctx;

    int ret = 0;

    int keybits = 256;

    char buf[16] = { 0 };

    mbedtls_aes_init( &ctx );

    ret = mbedtls_aes_setkey_dec( &ctx, key, keybits );   //swtich to decode
    if(ret != 0)
    {
        printf("swtich decode fail\n");
        return 1;
    }

    ret = bedtls_aes_crypt_ecb(&ctx, 0, data, buf);
    if(ret != 0)
    {
        printf("decode fail\n");
        return 2;
    }

    printf("%s\n", buf);
}



int mbedtls_aes_self_test( int verbose )
{
	int ret = 0, i, j, u, mode;
	unsigned int keybits;
	unsigned char key[32];
	unsigned char buf[64];
	const unsigned char *aes_tests;

	mbedtls_aes_context ctx;
	memset( key, 0, 32 );
	mbedtls_aes_init( &ctx );

	/*
	 * ECB mode
	 */
	for( i = 0; i < 6; i++ )
	{
		u = i >> 1;
		keybits = 128 + u * 64;
		mode = i & 1;

		if( verbose != 0 )
			mbedtls_printf( "  AES-ECB-%3u (%s): ", keybits,
					( mode == MBEDTLS_AES_DECRYPT ) ? "dec" : "enc" );

		memset( buf, 0, 16 );

		if( mode == MBEDTLS_AES_DECRYPT )
		{
			ret = mbedtls_aes_setkey_dec( &ctx, key, keybits );
			aes_tests = aes_test_ecb_dec[u];
		}
		else
		{
			ret = mbedtls_aes_setkey_enc( &ctx, key, keybits );
			aes_tests = aes_test_ecb_enc[u];
		}

		/*
		 * AES-192 is an optional feature that may be unavailable when
		 * there is an alternative underlying implementation i.e. when
		 * MBEDTLS_AES_ALT is defined.
		 */
		if( ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED && keybits == 192 )
		{
			mbedtls_printf( "skipped\n" );
			continue;
		}
		else if( ret != 0 )
		{
			goto exit;
		}

		for( j = 0; j < 10000; j++ )
		{
			ret = mbedtls_aes_crypt_ecb( &ctx, mode, buf, buf );
			if( ret != 0 )
				goto exit;
		}

		if( memcmp( buf, aes_tests, 16 ) != 0 )
		{
			ret = 1;
			goto exit;
		}

		if( verbose != 0 )
			mbedtls_printf( "passed\n" );
	}

	if( verbose != 0 )
		mbedtls_printf( "\n" );
exit:
	return ret;
}
