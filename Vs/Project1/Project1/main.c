#include <stdio.h>
#include <string.h>
#include "Source.h"
#include "EncryptionRsa.h"



int main()
{
	char pub_key[] = "C:\\Users\\Administrator\\Desktop\\bin\\pub_key.txt";
	char priv_key[] = "C:\\Users\\Administrator\\Desktop\\bin\\priv_key.txt";
	generate_pcpubkey_byte64(pub_key, priv_key);

#if 0
	char buf[] = "hello world";
	char receive[16] = { 0 };
	char receive1[16] = { 0 };

	char key1[] = "123456789";
	char key2[] = "123456789";
	int ret = 0;
	encryption_data(buf, receive, key1);


	bin_file_encryption();

	dacoda_file();
#endif
	while (1);
	return 0;
}

