#include <stdio.h>
#include <string.h>
#include "Source.h"


int main()
{
#if 0
	char buf[] = "hello world";
	char receive[16] = { 0 };
	char receive1[16] = { 0 };

	char key1[] = "123456789";
	char key2[] = "123456789";
	int ret = 0;
	encryption_data(buf, receive, key1);
#endif

	bin_file_encryption();

	dacoda_file();

	while (1);
	return 0;
}

