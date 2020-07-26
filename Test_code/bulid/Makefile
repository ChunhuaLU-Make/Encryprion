exe: test.o main.o
	gcc test.o main.o -o exe -I../mbedtls -L ../lib -lmbedcrypto
	rm -f *.o

test.o: ../test.c
	gcc -c ../test.c -o test.o

main.o: ../main.c
	gcc -c ../main.c -o main.o

.PHONY:
debug:
	gcc -g ../test.c ../main.c -o exeDebug -I../mbedtls -L ../lib -lmbedcrypto

clean:
	rm -fi exe
