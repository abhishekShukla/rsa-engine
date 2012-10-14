//
//  main.c
//  rsa_engine
//
//  Created by Abhishek Shukla Ravishankara on 10/6/12.
//  Copyright (c) 2012 Abhishek Shukla Ravishankara. All rights reserved.
//

#include "rsa.h"


int main(int argc, char **argv){
    
    int usage_error = 0;
    FILE *fp = NULL;
    int filePointer;
    FILE* fp_in = NULL;
    FILE* fp_out = NULL;
    
    if(argc == 6){
        //GenRsa
        if(strcmp(argv[1], "genRsa") == 0){
            printf("Need to generate rsa\n");
            
            private_key ku;
            public_key kp;
            
            // Initialize public key
            mpz_init(kp.n);
            mpz_init(kp.e);
            
            // Initialize private key
            mpz_init(ku.n);
            mpz_init(ku.e);
            mpz_init(ku.d);
            mpz_init(ku.p);
            mpz_init(ku.q);
            mpz_init(ku.d_mod_p_1);
            mpz_init(ku.d_mod_q_1);
            mpz_init(ku.co_ef);
            
            
            //Generate Keys
            generate_keys(&ku, &kp);

            //Generate Private Der
            fp=fopen(argv[2], "wb+");
            if(fp == NULL){
                printf("ERROR in opening file\n");
                exit(1);
            }
            generate_private_der(fp, ku);
            
            // Reading der and encoding to pem
            fp=fopen(argv[2], "rb+");
            if(fp == NULL){
                printf("ERROR in opening file\n");
                exit(1);
            }
            
            filePointer = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC);
            
            if(filePointer < 0){
                printf("ERROR in opening file\n");
                exit(1);
            }
            generate_private_pem_from_der(fp, filePointer);
            
            
            // Writing Public Der
            fp=fopen(argv[4], "w+");
            if(fp == NULL){
                printf("ERROR in opening file\n");
                exit(1);
            }
            generate_public_der(fp, kp);
            
            // Reading der and encoding to pem
            fp=fopen(argv[4], "rb+");
            if(fp == NULL){
                printf("ERROR in opening file\n");
                exit(1);
            }
            
            filePointer = open(argv[5], O_WRONLY | O_CREAT | O_TRUNC);
            
            if(filePointer < 0){
                printf("ERROR in opening file\n");
                exit(1);
            }
            generate_public_pem_from_der(fp, filePointer);
            
        }
        else{
            usage_error = 1;
        }
    }
    else if(argc == 5){
        //Encrypt or Decrypt
        if(strcmp(argv[1], "encrypt") == 0){
            
            //Decoding pem to der public
            fp = fopen(argv[2], "r");
            if(fp == NULL){
                printf("ERROR in opening file\n");
                exit(1);
            }
            filePointer = open("temp_base64_decoded.der", O_WRONLY | O_CREAT | O_TRUNC) ;
            if(filePointer < 0){
                printf("ERROR in opening file\n");
                exit(1);
            }
            generate_public_der_from_pem(fp, filePointer);
            
            //Extracting public key
            public_key kp_decoded;
            mpz_init(kp_decoded.n);
            mpz_init(kp_decoded.e);
            fp = fopen("temp_base64_decoded.der", "rb");
            if(fp == NULL){
                printf("ERROR in opening file\n");
                exit(1);
            }
            read_public_der(fp, &kp_decoded);
            
            
            //NOW ENCRYPT
            fp_in = fopen(argv[3], "r");
            if(fp_in == NULL){
                printf("ERROR in opening file\n");
                exit(1);
            }
            fp_out = fopen(argv[4], "w+");
            if(fp_out == NULL){
                printf("ERROR in opening file\n");
                exit(1);
            }
            encrypt_input_files(fp_in, fp_out, &kp_decoded);
            
        }        
        else if(strcmp(argv[1], "decrypt") == 0){
            printf("Need to decrypt\n");
            
            // pem back to der and base64 decoder
            fp = fopen(argv[2], "r");
            filePointer = open("temp_private_base64_decoded.der", O_WRONLY | O_CREAT | O_TRUNC) ;
            if(filePointer < 0){
                printf("ERROR in opening file\n");
                exit(1);
            }
            generate_private_der_from_pem(fp, filePointer);

            //Extract private key from der
            private_key ku_decoded;
            
            mpz_init(ku_decoded.n);
            mpz_init(ku_decoded.e);
            mpz_init(ku_decoded.d);
            mpz_init(ku_decoded.p);
            mpz_init(ku_decoded.q);
            mpz_init(ku_decoded.d_mod_p_1);
            mpz_init(ku_decoded.d_mod_q_1);
            mpz_init(ku_decoded.co_ef);
            
            fp = fopen("temp_private_base64_decoded.der", "rb");
            if(fp == NULL){
                printf("ERROR in opening file\n");
                exit(1);
            }
            read_private_der(fp, &ku_decoded);
            
            //NOW DECRYPT
            fp_in = fopen(argv[3], "rb+");
            if(fp_in == NULL){
                printf("ERROR in opening file\n");
                exit(1);
            }
            fp_out = fopen(argv[4], "w+");
            if(fp_out == NULL){
                printf("ERROR in opening file\n");
                exit(1);
            }
            
            decrypt_input_files(fp_in, fp_out, &ku_decoded);
            
        }
        else{
            usage_error = 1;
        }
    }
    else{
        usage_error = 1;
    }
    if(usage_error == 1){
        printf("USAGE:\n./main [OPTIONS] [ARGUMENTS] \n\tOPTIONS\n");
        printf("\t\tgenRsa: <private key der file> <private_key pem file> <public key der file> <public pem file>\n");
        printf("\t\tencrypt <public key pem file> <input file> <encrypted file>\n");
        printf("\t\tdecrypt <private key file> <input encrypted file> <decrypted file>");

    }
    return 0;
}


