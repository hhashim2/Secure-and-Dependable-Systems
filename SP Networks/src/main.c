/*
 * scrypt/src/main.c --
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "scrypt.h"

int main(int argc, char *argv[])
{
	uint32_t key = 0x98267351; 
	unsigned char* cleartext = (unsigned char*) "secret";
	size_t len = strlen((char*) cleartext);
	unsigned char ciphertext[len];
	
	printf("Encrypting text: %s\n", cleartext);
	sc_enc_ecb(cleartext, ciphertext, len, key);
	printf("Encrypted Text in ECM: %s\n\n\n", ciphertext);

	uint8_t ivec = 0x42;
	unsigned char* cleartext2 = (unsigned char*) "hacker";
	size_t len2 = strlen((char*) cleartext2);
	unsigned char ciphertext2[len2];
	
	printf("Encrypting text: %s\n", cleartext2);
	sc_enc_cbc(cleartext2, ciphertext2, len2, key, ivec);
	printf("Encrypted Text in BCM: %s\n\n\n", ciphertext2);

	uint8_t ciphertext3 [] = {0xc6, 0x5e, 0x05, 0x94, 0x6b, 0x86, 0xeb, 0x2e, 0x33, 0xf5, 0x8f, 0xda, 0xff, 0x0f, 0x42};
	size_t len3 = strlen((char*) ciphertext3);
	unsigned char cleartext3[len3];
	
	printf("Decrypting text: %s\n", (char*)ciphertext3);
	sc_dec_cbc(ciphertext3, cleartext3, len3, key, ivec);
	printf("Decrypted Text using CBC: %s\n", (char*)cleartext3);

	return EXIT_SUCCESS;
}
