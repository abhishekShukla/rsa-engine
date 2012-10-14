//
//  rsaFileio.c
//  rsa_engine
//
//  Created by Abhishek Shukla Ravishankara on 10/11/12.
//  Copyright (c) 2012 Abhishek Shukla Ravishankara. All rights reserved.
//

#include "rsa.h"

void generate_private_der(FILE* fp, private_key ku){
    
    char *final_packet;
    final_packet = (char*)malloc(2048);
    
    char hexValue[2];
    build_private_packet(ku, final_packet);
    printf("%s\n", final_packet);
    
    //Writing private der
    // final output
    for(int i = 0; i < strlen(final_packet); i = i + 2){
        
        hexValue[0] = (uint8_t)final_packet[i];
        
        if(i + 1 < strlen(final_packet)){
            hexValue[1] = (uint8_t)final_packet[i + 1];
        }
        fprintf(fp,"%c", (unsigned char) hex_to_int(hexValue));
    }
    //free(final_packet);
    fclose(fp);
    
}

void generate_private_pem_from_der(FILE* fp, int filePointer){
    
    // Reading der and encoding to pem
    unsigned char *input_encoder;
    
    fseek (fp , 0 , SEEK_END);
    size_t lSize = ftell (fp);
    rewind (fp);
    
    input_encoder = (unsigned char*) malloc (sizeof(unsigned char)*lSize);
    
    size_t n = fread(input_encoder, 1, lSize, fp);
    printf("%ld\n", n);
    fclose(fp);
    
    
    char *result_encoder;
    result_encoder = (char*)malloc(4096);
    
    int x = base64encode(input_encoder, lSize, result_encoder);
    
    printf("file pointer: %d\n", filePointer);
    
    write(filePointer,"-----BEGIN RSA PRIVATE KEY-----",31);
    write(filePointer, "\n" ,1);
    
    for(int i = 0; i < strlen(result_encoder); i++){
        
        if((i % 64) == 0 && i > 0){
            write(filePointer, "\n" ,1);
            printf("\n");
        }
        printf("%c",result_encoder[i]);
        write(filePointer, (const char *)&result_encoder[i], 1);
        
        //fprintf(fp,"%c", result_encoder[i]);
    }
    write(filePointer, "\n" ,1);
    write(filePointer,"-----END RSA PRIVATE KEY-----",29);
    write(filePointer, "\n" ,1);
    close(filePointer);
    
    printf("\n");
    
    
}

void generate_public_der(FILE* fp, public_key kp){
    
    char *final_public_packet;
    final_public_packet = (char*)malloc(1024);
    char hexValue[2];
    
    build_public_packet(kp, final_public_packet);
    printf("%s\n", final_public_packet);
    
    // Writing Public Der
    if(fp == NULL){
        printf("ERROR!\n");
    }
    
    // final output
    for(int i = 0; i < strlen(final_public_packet); i = i + 2){
        
        hexValue[0] = (uint8_t)final_public_packet[i];
        
        if(i + 1 < strlen(final_public_packet)){
            hexValue[1] = (uint8_t)final_public_packet[i + 1];
        }
        fprintf(fp,"%c", (unsigned char) hex_to_int(hexValue));
    }
    
    //free(final_packet);
    fclose(fp);
    
}

void generate_public_pem_from_der(FILE* fp, int filePointer){
    
    unsigned char *input_encoder_public;
    
    fseek (fp , 0 , SEEK_END);
    size_t lSize = ftell (fp);
    rewind (fp);
    
    input_encoder_public = (unsigned char*) malloc (sizeof(unsigned char)*lSize);
    
    size_t n = fread(input_encoder_public, 1, lSize, fp);
    printf("%ld\n", n);
    fclose(fp);
    
    char *result_encoder_public;
    result_encoder_public = (char*)malloc(4096);
    
    size_t x = base64encode(input_encoder_public, lSize, result_encoder_public);
    
    printf("file pointer: %d\n", filePointer);
    
    write(filePointer,"-----BEGIN PUBLIC KEY-----",26);
    write(filePointer, "\n" ,1);
    
    for(int i = 0; i < strlen(result_encoder_public); i++){
        
        if((i % 64) == 0 && i > 0){
            write(filePointer, "\n" ,1);
            printf("\n");
        }
        printf("%c",result_encoder_public[i]);
        write(filePointer, (const char *)&result_encoder_public[i], 1);
        
    }
    write(filePointer, "\n" ,1);
    write(filePointer,"-----END PUBLIC KEY-----",24);
    write(filePointer, "\n" ,1);
    close(filePointer);
    
    printf("\n");
    
}

void generate_private_der_from_pem(FILE* fp, int filePointer){
    
    fseek (fp , 0 , SEEK_END);
    size_t lSize = ftell (fp);
    rewind (fp);
    
    char *input_decoder;
    input_decoder = (char*) malloc (sizeof(char)*lSize);
    
    char *temp;
    temp = (char*) malloc (80);
    
    fgets(temp, 64, fp);
    //printf("%s", temp);
    
    fseek(fp , 0 , 32);
    size_t n = fread(input_decoder, 1, lSize - 63, fp);
    printf("\n\n%s", input_decoder);
    
    fclose(fp);
    
    unsigned char *result_decoder;
    result_decoder = (unsigned char*) malloc (sizeof(unsigned char)*4096);
    
    int x = base64decode(input_decoder, strlen(input_decoder), result_decoder);
    
    for(int i = 0; i < x; i++){
        
        //printf("%c",result_decoder[i]);
        write(filePointer, (const unsigned char *)&result_decoder[i], 1);
        
    }
    
    close(filePointer);
    printf("\n");
}

void generate_public_der_from_pem(FILE *fp, int filePointer){
    
    // pem back to der and base64 decoder
    
    fseek (fp , 0 , SEEK_END);
    size_t lSize = ftell (fp);
    rewind (fp);
    
    char *input_decoder_public;
    input_decoder_public = (char*) malloc (sizeof(char)*lSize);
    
    
    char *temp_public;
    temp_public = (char*) malloc (80);
    
    fgets(temp_public, 54, fp);
    
    //printf("%s", temp);
    
    fseek(fp , 0 , 28);
    size_t n = fread(input_decoder_public, 1, lSize - 52, fp);
    printf("\nInput Decoder Public\n%s", input_decoder_public);
    
    fclose(fp);
    
    
    unsigned char *result_decoder_public;
    result_decoder_public = (unsigned char*) malloc (sizeof(unsigned char)*4096);
    
    size_t x = base64decode(input_decoder_public, strlen(input_decoder_public), result_decoder_public);
    
    
    
    for(int i = 0; i < x; i++){
        
        //printf("%c",result_decoder[i]);
        write(filePointer, (const unsigned char *)&result_decoder_public[i], 1);
        
    }
    
    close(filePointer);
    printf("\n");
}

void encrypt_input_files(FILE *fp_in, FILE* fp_out, public_key *kp){
    
    unsigned char *cipher_text;
    cipher_text = (unsigned char*) malloc (kp->modulus_size);
    
    char *message;
    fseek (fp_in , 0 , SEEK_END);
    size_t lSize = ftell (fp_in);
    rewind (fp_in);
    
    message = (char*) malloc (lSize);
    
    size_t n = fread(message, 1, lSize, fp_in);
    printf("%ld\n", n);
    fclose(fp_in);
    
    size_t cipher_length = enrypt(kp->n, kp->modulus_size, kp->e, message, lSize, &cipher_text);
    for(int i = 0; i < cipher_length; i = i + 1){
        printf("%.02x", cipher_text[i]);
    }
    
    //Writing cipher text
    if(fp_out == NULL){
        printf("ERROR!\n");
    }
    for(int i = 0; i < cipher_length; i++){
        fprintf(fp_out, "%c", cipher_text[i]);
    }
    printf("\n");
    fclose(fp_out);
    
}

void decrypt_input_files(FILE *fp_in, FILE* fp_out, private_key *ku){
    
    unsigned char *plain_text;
    plain_text = (unsigned char*) malloc (ku->modulus_size);
    
    fseek (fp_in , 0 , SEEK_END);
    size_t lSize = ftell (fp_in);
    rewind (fp_in);
    
    unsigned char *cipher_text;
    cipher_text = (unsigned char*) malloc (sizeof(unsigned char)*lSize);
    
    size_t n = fread(cipher_text, 1, lSize, fp_in);
    fclose(fp_in);
    
    size_t text_length = decrypt(ku->n, ku->modulus_size, ku->d, cipher_text, lSize, &plain_text);
    
    //Writing plain text
    printf("Plain Text\n");
    for(int i = 0; i < text_length; i++){
        printf("%c", plain_text[i]);
    }
    
    if(fp_out == NULL){
        printf("ERROR!\n");
    }
    for(int i = 0; i < text_length; i++){
        fprintf(fp_out, "%c", plain_text[i]);
    }
    fclose(fp_out);
    printf("\n");
    
}
