CC = gcc
LIBS = -I/usr/local/include -L/usr/local/lib -lgmp

all : main

main: main.o base64EncDec.o EncryptionDecryption.o rsaHelpers.o rsaFileio.o
	${CC} -o main main.o base64EncDec.o EncryptionDecryption.o rsaHelpers.o rsaFileio.o ${LIBS} -std=gnu99
main.o: main.c
	${CC} -c main.c -std=gnu99

base64EncDec.o: base64EncDec.c
	${CC} -c base64EncDec.c -std=gnu99

EncryptionDecryption.o: EncryptionDecryption.c
	${CC} -c EncryptionDecryption.c -std=gnu99

rsaHelpers.o: rsaHelpers.c
	${CC} -c rsaHelpers.c -std=gnu99

rsaFileio.o: rsaFileio.c
	${CC} -c rsaFileio.c -std=gnu99

clean : 
	rm main rsaFileio.o main.o base64EncDec.o EncryptionDecryption.o rsaHelpers.o *.pem *.der
