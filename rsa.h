//
//  rsa.h
//  rsa_engine
//
//  Created by Abhishek Shukla Ravishankara on 10/8/12.
//  Copyright (c) 2012 Abhishek Shukla Ravishankara. All rights reserved.
//

#ifndef rsa_engine_rsa_h
#define rsa_engine_rsa_h

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <gmp.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#define DEBUG
#define VALUE_REQUIRED 1
#define VALUE_NOT_REQUIRED 0
#define MODULUS_SIZE 1024                /* This is the number of bits we want in the modulus */
#define BLOCK_SIZE (MODULUS_SIZE/8)         /* This is the size of a block that gets en/decrypted at once */
#define BUFFER_SIZE ((MODULUS_SIZE/8) / 2)  /* This is the number of bytes in n and p */

typedef struct {
    
    size_t modulus_size; /* size of modulus */
    mpz_t n; /* Modulus */
    
    size_t e_size; /* size of public exponent */
    mpz_t e; /* Public Exponent */
    
} public_key;

typedef struct {
    size_t header; /* header */
    
    size_t version_size; /* size of the version */
    mpz_t version; /* version = 00 */
    
    size_t modulus_size; /* size of modulus */
    mpz_t n; /* Modulus */
    
    size_t e_size; /* size of public exponent */
    mpz_t e; /* Public Exponent */
    
    size_t d_size; /* size of private exponent */
    mpz_t d; /* Private Exponent */
    
    size_t p_size; /* size of p */
    mpz_t p; /* Starting prime p */
    
    size_t q_size; /* size of q */
    mpz_t q; /* Starting prime q */
    
    size_t exp1_size; /* size of exponent 1 */
    mpz_t d_mod_p_1; /* exponent 1 */
    
    size_t exp2_size; /*size of exponent2 */
    mpz_t d_mod_q_1; /* exponent 2 */
    
    size_t co_ef_size; /* size of co-efficient */
    mpz_t co_ef; /* co-effcient */
    
    mpz_t temp;
    
} private_key;

typedef struct {
    
    uint8_t raw[1024];
    uint8_t seperator;
    size_t length_indicator;
    size_t length;
    unsigned char value[1024];
    
} decode_format;


int base64encode(const void*, size_t, char*);
int base64decode(const void*, size_t, unsigned char*);
size_t enrypt(mpz_t, size_t, mpz_t, char*, size_t, unsigned char**);
size_t decrypt(mpz_t, size_t, mpz_t, unsigned char*, size_t, unsigned char**);
void generate_keys(private_key*, public_key*);

void PRINT_HEX(size_t);
size_t format_public_header(size_t, char*);
size_t format_private_header(size_t, char*);
size_t format_keys(mpz_t, size_t, char *);
int hex_to_int(char *);
void build_public_packet(public_key, char*);
void build_private_packet(private_key, char*);
size_t break_string_sequence(unsigned char*, size_t, size_t, uint8_t, uint8_t, decode_format*, int);
void read_public_der(FILE*, public_key*);
void read_private_der(FILE*, private_key*);
unsigned char generate_random_octet();

void generate_private_der(FILE *, private_key);
void generate_private_pem_from_der(FILE *, int);
void generate_public_der(FILE*, public_key);
void generate_public_pem_from_der(FILE *, int);
void generate_private_der_from_pem(FILE *, int);
void generate_public_der_from_pem(FILE *, int);
void encrypt_input_files(FILE *, FILE *, public_key *);
void decrypt_input_files(FILE *, FILE *, private_key *);






#endif
