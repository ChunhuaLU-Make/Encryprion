#include <stdio.h>
#include <string.h>
#include "test.h"


int main()
{
	char buf[] = "hello world";
	char receive[16] = { 0 };
	char receive1[16] = { 0 };

	char key1[] = "123456789";
	char key2[] = "123456789";
	int ret = 0;

	encryption_test(buf, key1);

	return 0;
}

