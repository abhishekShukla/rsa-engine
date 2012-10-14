//
//  EncryptionDecryption.c
//  rsa_engine
//
//  Created by Abhishek Shukla Ravishankara on 10/10/12.
//  Copyright (c) 2012 Abhishek Shukla Ravishankara. All rights reserved.
//

#include "rsa.h"

/* NOTE: Assumes mpz_t's are initted in ku and kp */
void generate_keys(private_key* ku, public_key* kp){
    char buf[BUFFER_SIZE];
    int i;
    mpz_t phi; mpz_init(phi);
    mpz_t tmp1; mpz_init(tmp1);
    mpz_t tmp2; mpz_init(tmp2);
    
    srand(time(NULL));
    
    /* Instead of selecting e st. gcd(phi, e) = 1; 1 < e < phi, lets choose e
     * first then pick p,q st. gcd(e, p-1) = gcd(e, q-1) = 1 */
    // We'll set e globally.  I've seen suggestions to use primes like 3, 17 or
    // 65537, as they make coming calculations faster.  Lets use 3.
    mpz_set_ui(ku->e, 3);
    
    /* Select p and q */
    /* Start with p */
    // Set the bits of tmp randomly
    for(i = 0; i < BUFFER_SIZE; i++)
        buf[i] = rand() % 0xFF;
    
    // Set the top two bits to 1 to ensure int(tmp) is relatively large
    buf[0] |= 0xC0;
    
    // Set the bottom bit to 1 to ensure int(tmp) is odd (better for finding primes)
    buf[BUFFER_SIZE - 1] |= 0x01;
    
    // Interpret this char buffer as an int
    mpz_import(tmp1, BUFFER_SIZE, 1, sizeof(buf[0]), 0, 0, buf);
    
    // Pick the next prime starting from that random number
    mpz_nextprime(ku->p, tmp1);
    
    /* Make sure this is a good choice*/
    mpz_mod(tmp2, ku->p, ku->e);        /* If p mod e == 1, gcd(phi, e) != 1 */
    
    while(!mpz_cmp_ui(tmp2, 1))
    {
        mpz_nextprime(ku->p, ku->p);    /* so choose the next prime */
        mpz_mod(tmp2, ku->p, ku->e);
    }
    
    /* Now select q */
    
    do {
        for(i = 0; i < BUFFER_SIZE; i++)
            buf[i] = rand() % 0xFF;
        
        // Set the top two bits to 1 to ensure int(tmp) is relatively large
        buf[0] |= 0xC0;
        
        // Set the bottom bit to 1 to ensure int(tmp) is odd
        buf[BUFFER_SIZE - 1] |= 0x01;
        
        // Interpret this char buffer as an int
        mpz_import(tmp1, (BUFFER_SIZE), 1, sizeof(buf[0]), 0, 0, buf);
        
        // Pick the next prime starting from that random number
        mpz_nextprime(ku->q, tmp1);
        mpz_mod(tmp2, ku->q, ku->e);
        
        while(!mpz_cmp_ui(tmp2, 1))
        {
            mpz_nextprime(ku->q, ku->q);
            mpz_mod(tmp2, ku->q, ku->e);
        }
    } while(mpz_cmp(ku->p, ku->q) == 0); /* If we have identical primes (unlikely), try again */
    
    
    /* Calculate n = p x q */
    mpz_mul(ku->n, ku->p, ku->q);
    
    /* Compute phi(n) = (p-1)(q-1) */
    mpz_sub_ui(tmp1, ku->p, 1);
    mpz_sub_ui(tmp2, ku->q, 1);
    mpz_mul(phi, tmp1, tmp2);
    
    /* Calculate d (multiplicative inverse of e mod phi) */
    if(mpz_invert(ku->d, ku->e, phi) == 0)
    {
        mpz_gcd(tmp1, ku->e, phi);
        printf("gcd(e, phi) = [%s]\n", mpz_get_str(NULL, 16, tmp1));
        printf("Invert failed\n");
    }
    
    /* Calculate Exponent 1 d mod (p - 1) */
    mpz_sub_ui(tmp1, ku->p, 1);
    mpz_mod(ku->d_mod_p_1, ku->d, tmp1);
    
    /* Calculate Exponent 2 d mod (q - 1) */
    mpz_sub_ui(tmp1, ku->q, 1);
    mpz_mod(ku->d_mod_q_1, ku->d, tmp1);
    
    /* Calculate Co-efficient (q ^ -1) mod p
     Chinese remainder theorem coefficient (inverse of q mod p) */
    mpz_invert(ku->co_ef, ku->q, ku->p);
    
    /* if coefficient is negative, then add p to make it positive */
    if (mpz_sgn(ku->co_ef) == -1) {
        mpz_add(ku->co_ef, ku->co_ef, ku->p);
    }
    
    
    
    mpz_set_str(ku->version, "0", 16);
    
    ku->version_size = strlen(mpz_get_str(NULL, 16, ku->version));
    ku->modulus_size = strlen(mpz_get_str(NULL, 16, ku->n));
    ku->e_size = strlen(mpz_get_str(NULL, 16, ku->e));
    ku->d_size = strlen(mpz_get_str(NULL, 16, ku->d));
    ku->p_size = strlen(mpz_get_str(NULL, 16, ku->p));
    ku->q_size = strlen(mpz_get_str(NULL, 16, ku->q));
    ku->exp1_size = strlen(mpz_get_str(NULL, 16, ku->d_mod_p_1));
    ku->exp2_size = strlen(mpz_get_str(NULL, 16, ku->d_mod_q_1));
    ku->co_ef_size = strlen(mpz_get_str(NULL, 16, ku->co_ef));
    
    
    /*
     ku->version = 0;
     ku->version_size = 1;
     ku->modulus_size = mpz_size(ku->n);
     ku->e_size = mpz_size(ku->e);
     ku->d_size = mpz_size(ku->d);
     ku->p_size = mpz_size(ku->p);
     ku->q_size = mpz_size(ku->q);
     ku->exp1_size = mpz_size(ku->d_mod_p_1);
     ku->exp2_size = mpz_size(ku->d_mod_q_1);
     ku->co_ef_size = mpz_size(ku->co_ef);
     
     
     /* Calculating all sizes
     
     ku->version_size = mpz_sizeinbase(ku->version, 16);
     ku->modulus_size = mpz_sizeinbase(ku->n, 16);
     ku->e_size = mpz_sizeinbase(ku->e, 16);
     ku->d_size = mpz_sizeinbase(ku->d, 16);
     ku->p_size = mpz_sizeinbase(ku->p, 16);
     ku->q_size = mpz_sizeinbase(ku->q, 16);
     ku->exp1_size = mpz_sizeinbase(ku->d_mod_p_1, 16);
     ku->exp2_size = mpz_sizeinbase(ku->d_mod_q_1, 16);
     ku->co_ef_size = mpz_sizeinbase(ku->co_ef, 16);
     */
    
    /* Set public key */
    mpz_set(kp->e, ku->e);
    mpz_set(kp->n, ku->n);
    
    kp->modulus_size = strlen(mpz_get_str(NULL, 16, kp->n));
    kp->e_size = strlen(mpz_get_str(NULL, 16, kp->e));
    
    return;
}


size_t enrypt(mpz_t n, size_t modulus_size, mpz_t e, char* message, size_t message_length, unsigned char** cipher_text){
    
    if(message_length > modulus_size - 11){
        printf("Message too long\n");
        return 0;
    }
    
    unsigned char* encoded_message;
    unsigned char* random_octet;
    size_t random_octet_length = modulus_size - message_length - 3;
    int i;
    
    mpz_t message_t;
    mpz_t cipher_t;
    size_t cipher_length;
    
    mpz_init(message_t);
    mpz_init(cipher_t);
    
    encoded_message = (unsigned char*) malloc (modulus_size);
    random_octet = (unsigned char*) malloc (random_octet_length);
    
    encoded_message[0] = (unsigned char)0x00;
    encoded_message[1] = (unsigned char)0x02;
    
    for(i = 0; i < random_octet_length; i++){
        random_octet[i] = generate_random_octet();
    }
    
    for(i = 0; i < random_octet_length; i++){
        encoded_message[i + 2] = random_octet[i];
        //printf("I = %d\n", i);
    }
    
    encoded_message[random_octet_length + 2] = (unsigned char)0x00;
    
    for(int j = 0; j < message_length; j++){
        encoded_message[random_octet_length + 3 + j] = message[j];
    }
    
    printf("Encoded Message\n");
    for(int j = 0; j < modulus_size; j++){
        printf("%.02x", encoded_message[j]);
    }
    printf("\n");
    
    mpz_import(message_t, modulus_size, 1, sizeof(encoded_message[0]), 0, 0, encoded_message);
    mpz_powm(cipher_t,message_t,e,n);
    
    *cipher_text= (unsigned char*)mpz_export(NULL, &cipher_length, 1, 1, 0, 0, cipher_t);
    
    printf("Cipher Text\n");
    for(int j = 0; j < cipher_length; j++){
        printf("%.02x", cipher_text[j]);
    }
    printf("\n");
    
    printf("The length of the ciphertext = %ld\n", cipher_length);
    
    return cipher_length;
    
}

size_t decrypt(mpz_t n, size_t modulus_size, mpz_t d, unsigned char* cipher_text, size_t cipher_length, unsigned char** result){
    
    mpz_t cipher_t;
    mpz_t message_t;
    size_t message_length;
    
    unsigned char* temp_final;
    temp_final = (unsigned char*) malloc(modulus_size);
    
    mpz_init(message_t);
    mpz_init(cipher_t);
    
    mpz_import(cipher_t, modulus_size, 1, sizeof(cipher_text[0]),0,0, cipher_text);
    mpz_powm(message_t, cipher_t, d, n);
    
    
    
    unsigned char* temp = (unsigned char *)mpz_export(NULL,&message_length, 1, 1, 0, 0, message_t);
    
    
    //printf("%s", mpz_get_str(NULL, 16, message_t));
    
    if(message_length < modulus_size){
        
        int i;
        for(i = 0; i < (modulus_size - message_length); i++){
            temp_final[i] = (unsigned char)(0);
        }
        memcpy(temp_final + i, temp, message_length);
        message_length = message_length + i;
        
        for(int i = 0; i < modulus_size; i++){
            printf("%.02x", temp_final[i]);
        }
        printf("\n");
        
    }
    else if(message_length > modulus_size){
        printf("Decryption Failed\n");
        return 0;
    }
    else if(message_length == modulus_size){
        temp_final = temp;
    }
    printf("The length of the message = %ld\n", message_length);
    //Check padding
    
    int index = 0;
    if(temp_final[index++] != 0x00){
        
        printf("Decryption Failed\n");
        return 0;
    }
    
    if(temp_final[index++] != 0x02){
        printf("Decryption Failed\n");
        return 0;
    }
    
    int count_random_octet = 0;
    
    while(temp_final[index++] != 0x00){
        count_random_octet = count_random_octet + 1;
    }
    
    if(count_random_octet < 8){
        printf("Decryption Failed\n");
        return 0;
    }
    
    memcpy(*result, temp_final + index, message_length - index);
    
    return message_length - index;
}