#include "EncryptionRsa.h"

#include "platform.h"
#include "entropy.h"
#include "ctr_drbg.h"



//#define __OpenBSD__

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
#if !defined(__OpenBSD__)
	size_t i;

	if (rng_state != NULL)
		rng_state = NULL;

	for (i = 0; i < len; ++i)
		output[i] = rand();
#else
	if (rng_state != NULL)
		rng_state = NULL;

	arc4random_buf(output, len);
#endif /* !OpenBSD */

	return 0;

}

/**
* get random number
*/
int generate_random1_byte8(unsigned char random[32])
{
	int ret = 0;
	unsigned char output_random[32];
	mbedtls_ctr_drbg_context ctr_drbg;

	ret = mbedtls_ctr_drbg_random(&ctr_drbg, output_random, sizeof(output_random));
	if (ret != 0)
	{
		return 1;
	}
	memcpy(random, output_random, sizeof(output_random));
	return ret;
}

void transmit_pcpubkey_random(char* pub_key_path, unsigned char random[32])
{
	char buf[1024] = { 0 };
	FILE* fp = fopen(pub_key_path, "rb");
	if (fp == NULL)
	{
		printf("open %s file fail\n", pub_key_path);
		return;
	}
	
	while (1)
	{
		int length = fread(buf, 1, 1024, fp);
		if (length == 0)
		{
			break;
		}

		//transmit(buf, length);  TODO
	}

	fclose(fp);
}

/**
*
*/
void generate_pcpubkey_byte64(char* pub_key_path, char* priv_key_path)
{
	int ret = 1;
	int exit_code = MBEDTLS_EXIT_FAILURE;
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
	FILE *fpub = NULL;
	FILE *fpriv = NULL;
	const char *pers = "rsa_genkey";

	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
	mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&DP);
	mbedtls_mpi_init(&DQ); mbedtls_mpi_init(&QP);

	mbedtls_printf("\n  . Seeding the random number generator...");
	fflush(stdout);

	mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)pers,
		strlen(pers))) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE);
	fflush(stdout);

	if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
		EXPONENT)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n  . Exporting the public  key in rsa_pub.txt....");
	fflush(stdout);

	if ((ret = mbedtls_rsa_export(&rsa, &N, &P, &Q, &D, &E)) != 0 ||
		(ret = mbedtls_rsa_export_crt(&rsa, &DP, &DQ, &QP)) != 0)
	{
		mbedtls_printf(" failed\n  ! could not export RSA parameters\n\n");
		goto exit;
	}

	if ((fpub = fopen(pub_key_path, "wb+")) == NULL)
	{
		mbedtls_printf(" failed\n  ! could not open rsa_pub.txt for writing\n\n");
		goto exit;
	}

	if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, fpub)) != 0 ||
		(ret = mbedtls_mpi_write_file("E = ", &E, 16, fpub)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n  . Exporting the private key in rsa_priv.txt...");
	fflush(stdout);

	if ((fpriv = fopen(priv_key_path, "wb+")) == NULL)
	{
		mbedtls_printf(" failed\n  ! could not open rsa_priv.txt for writing\n");
		goto exit;
	}

	if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("E = ", &E, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("D = ", &D, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("P = ", &P, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("Q = ", &Q, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("DP = ", &DP, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("DQ = ", &DQ, 16, fpriv)) != 0 ||
		(ret = mbedtls_mpi_write_file("QP = ", &QP, 16, fpriv)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
		goto exit;
	}
	mbedtls_printf(" ok\n\n");

	exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

	if (fpub != NULL)
		fclose(fpub);

	if (fpriv != NULL)
		fclose(fpriv);

	mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
	mbedtls_mpi_free(&D); mbedtls_mpi_free(&E); mbedtls_mpi_free(&DP);
	mbedtls_mpi_free(&DQ); mbedtls_mpi_free(&QP);
	mbedtls_rsa_free(&rsa);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	mbedtls_printf("  Press Enter to exit this program.\n");
	fflush(stdout); getchar();

	mbedtls_exit(exit_code);
}

int get_sha1_sum(unsigned char plaintext[KEY_LEN], unsigned char sha1sum[20])
{
	if (mbedtls_sha1_ret(plaintext, PT_LEN, sha1sum) != 0)	//计算缓冲区的SHA-1校验和
	{
		return 1;	//get sha1sum fail
	}

	return 0;
}


int signature(mbedtls_rsa_context *rsa, unsigned char data[KEY_LEN], unsigned char sha1sum[20])
{
	int ret = 0;
	int verbose = 1;	//open log

	if (verbose != 0)
		mbedtls_printf("  PKCS#1 data sign  : ");

	if (mbedtls_rsa_pkcs1_sign(rsa, myrand, NULL,
		MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA1, 0,
		sha1sum, data) != 0)
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		return 1;
	}

	return 0;
}


int attestation(mbedtls_rsa_context *rsa, unsigned char data[KEY_LEN], unsigned char sha1sum[20])
{
	int verbose = 1;

	if (verbose != 0)
		mbedtls_printf("passed\n  PKCS#1 sig. verify: ");

	if (mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL,
		MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA1, 0,
		sha1sum, data) != 0)
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		return 1;
	}

	return 0;
}












































/*******************************************
********************************************
********************************************/
/**
* signature and attestation function
*/
void signature_attestation(int verbose)
{
	int ret = 0;

	size_t len;
	mbedtls_rsa_context rsa;
	unsigned char rsa_plaintext[PT_LEN];	//明文
	unsigned char rsa_decrypted[PT_LEN];	//译文
	unsigned char rsa_ciphertext[KEY_LEN];	//密文

	unsigned char sha1sum[20];

	mbedtls_mpi K;

	mbedtls_mpi_init(&K);
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_N));
	MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, &K, NULL, NULL, NULL, NULL));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_P));
	MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, NULL, &K, NULL, NULL, NULL));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_Q));
	MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, NULL, NULL, &K, NULL, NULL));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_D));
	MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, NULL, NULL, NULL, &K, NULL));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_E));
	MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, NULL, NULL, NULL, NULL, &K));

	MBEDTLS_MPI_CHK(mbedtls_rsa_complete(&rsa));

	if (verbose != 0)
		mbedtls_printf("  RSA key validation: ");

	if (mbedtls_rsa_check_pubkey(&rsa) != 0 ||
		mbedtls_rsa_check_privkey(&rsa) != 0)
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (verbose != 0)
		mbedtls_printf("passed\n  PKCS#1 encryption : ");

	memcpy(rsa_plaintext, RSA_PT, PT_LEN);

	if (mbedtls_rsa_pkcs1_encrypt(&rsa, myrand, NULL, MBEDTLS_RSA_PUBLIC,
		PT_LEN, rsa_plaintext,
		rsa_ciphertext) != 0)
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (verbose != 0)
		mbedtls_printf("passed\n  PKCS#1 decryption : ");

	if (mbedtls_rsa_pkcs1_decrypt(&rsa, myrand, NULL, MBEDTLS_RSA_PRIVATE,
		&len, rsa_ciphertext, rsa_decrypted,
		sizeof(rsa_decrypted)) != 0)
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (memcmp(rsa_decrypted, rsa_plaintext, len) != 0)
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (verbose != 0)
		mbedtls_printf("passed\n");

	/***********************************************/

	if (verbose != 0)
		mbedtls_printf("  PKCS#1 data sign  : ");

	if (mbedtls_sha1_ret(rsa_plaintext, PT_LEN, sha1sum) != 0)	//计算缓冲区的SHA-1校验和
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		return(1);
	}

	if (mbedtls_rsa_pkcs1_sign(&rsa, myrand, NULL,
		MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA1, 0,
		sha1sum, rsa_ciphertext) != 0)
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (verbose != 0)
		mbedtls_printf("passed\n  PKCS#1 sig. verify: ");

	if (mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL,
		MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA1, 0,
		sha1sum, rsa_ciphertext) != 0)
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (verbose != 0)
		mbedtls_printf("passed\n");

cleanup:
	mbedtls_mpi_free(&K);
	mbedtls_rsa_free(&rsa);

	return(ret);
}


/**
* 加密解密
*/
void rsa_test(int verbose)
{
	int ret = 0;

	size_t len;
	mbedtls_rsa_context rsa;
	unsigned char rsa_plaintext[PT_LEN];
	unsigned char rsa_decrypted[PT_LEN];
	unsigned char rsa_ciphertext[KEY_LEN];

	mbedtls_mpi K;

	mbedtls_mpi_init(&K);

	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_N));
	MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, &K, NULL, NULL, NULL, NULL));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_P));
	MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, NULL, &K, NULL, NULL, NULL));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_Q));
	MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, NULL, NULL, &K, NULL, NULL));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_D));
	MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, NULL, NULL, NULL, &K, NULL));
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, RSA_E));
	MBEDTLS_MPI_CHK(mbedtls_rsa_import(&rsa, NULL, NULL, NULL, NULL, &K));

	MBEDTLS_MPI_CHK(mbedtls_rsa_complete(&rsa));

	if (verbose != 0)
		mbedtls_printf("  RSA key validation: ");

	if (mbedtls_rsa_check_pubkey(&rsa) != 0 ||
		mbedtls_rsa_check_privkey(&rsa) != 0)
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (verbose != 0)
		mbedtls_printf("passed\n  PKCS#1 encryption : ");

	memcpy(rsa_plaintext, RSA_PT, PT_LEN);

	if (mbedtls_rsa_pkcs1_encrypt(&rsa, myrand, NULL, MBEDTLS_RSA_PUBLIC,
		PT_LEN, rsa_plaintext,
		rsa_ciphertext) != 0)
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (verbose != 0)
		mbedtls_printf("passed\n  PKCS#1 decryption : ");

	if (mbedtls_rsa_pkcs1_decrypt(&rsa, myrand, NULL, MBEDTLS_RSA_PRIVATE,
		&len, rsa_ciphertext, rsa_decrypted,
		sizeof(rsa_decrypted)) != 0)
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (memcmp(rsa_decrypted, rsa_plaintext, len) != 0)
	{
		if (verbose != 0)
			mbedtls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (verbose != 0)
		mbedtls_printf("passed\n");

	if (verbose != 0)
		mbedtls_printf("\n");

cleanup:
	mbedtls_mpi_free(&K);
	mbedtls_rsa_free(&rsa);

	return ret;

}
