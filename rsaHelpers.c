//
//  rsaHelpers.c
//  rsa_engine
//
//  Created by Abhishek Shukla Ravishankara on 10/11/12.
//  Copyright (c) 2012 Abhishek Shukla Ravishankara. All rights reserved.
//

#include "rsa.h"

void PRINT_HEX(size_t len){
    if(len <= 255){
        printf("[%02lx]", len);
    }
    else if(len >= 256){
        printf("[%04lx]", len);
    }
}

size_t format_public_header(size_t total_size, char* result){
    
    size_t size = 0;
    
    if(total_size <= 128){
        sprintf(result, "30%02lx", total_size);
        size = size + 2;
    }
    else if(total_size > 128 && total_size <= 256){
        sprintf(result, "3081%02lx", total_size);
        size = size + 3;
    }
    else if(total_size > 256){
        sprintf(result, "3082%04lx", total_size);
        size = size + 4;
    }
    
    strcat(result, "300d06092a864886f70d010101050003818b00308187");
    //strcat(result, "300d06092a864886f70d010101050003818d00308189");
    //size = size + 22;
    
    //printf("%s\n", result);
    
    return size;
}

size_t format_private_header(size_t total_size, char* result){
    
    size_t size = 0;
    
    if(total_size <= 128){
        sprintf(result, "30%02lx", total_size);
        size = size + 2;
    }
    else if(total_size > 128 && total_size <= 256){
        sprintf(result, "3081%02lx", total_size);
        size = size + 3;
    }
    else if(total_size > 256){
        sprintf(result, "3082%04lx", total_size);
        size = size + 4;
    }
    
    printf("%s\n", result);
    return size;
}

size_t format_keys(mpz_t value, size_t size, char *result){
    
    char size_str[1024];
    //char temp_data1[1024];
    char temp_data2[1024];
    char beginning_char = 'X';
    
    printf("Size is at beginning: %ld\n", size);
    
    for(int i = 0; i < sizeof(temp_data2); i++){
        temp_data2[i] = 0;
        size_str[i] = 0;
    }
    
    /* Copy the value into a data buffer */
    mpz_get_str(result, 16, value);
    
    //printf("Number of characters is: %ld\n", size);
    
    /* If size is odd need to place a zero in the beginning */
    if(size % 2 != 0){
        temp_data2[0] = '0';
        strncpy(temp_data2 + 1, result, strlen(result));
        strncpy(result, temp_data2, strlen(temp_data2));
        size = size + 1;
    }
    else{
        
    }
    
    beginning_char = result[0];
    
    /* MSB in HEX check */
    if(beginning_char == '8' || beginning_char == '9' || beginning_char == 'a' ||
       beginning_char == 'b' || beginning_char == 'c' || beginning_char == 'd' ||
       beginning_char == 'e' || beginning_char == 'f'){
        
        /* Then MSB in hex is one */
        /* So two zeroes have to be added */
        temp_data2[0] = '0';
        temp_data2[1] = '0';
        strncpy(temp_data2 + 2, result, strlen(result));
        strncpy(result, temp_data2, strlen(temp_data2));
        size = size + 2;
    }
    else{
        
        /* MSB in hex is not one*/
        /* Do nothing */
        
    }
    
    //printf("Number of characters At the end: %ld\n", size);
    size = size / 2;
    printf("Size is: %ld\n", size);
    
    if(size < 128){
        sprintf(size_str, "%02lx", size);
        strncpy(temp_data2, size_str, strlen(size_str));
        strncpy(temp_data2 + 2, result, strlen(result));
        strncpy(result, temp_data2, strlen(temp_data2));
        size = size + 1;
    }
    else if(size >= 128 && size < 256){
        sprintf(size_str, "81%02lx", size);
        strncpy(temp_data2, size_str, strlen(size_str));
        strncpy(temp_data2 + 4, result, strlen(result));
        strncpy(result, temp_data2, strlen(temp_data2));
        size = size + 2;
    }
    else if(size >= 256){
        sprintf(size_str, "82%04lx", size);
        strncpy(temp_data2, size_str, strlen(size_str));
        strncpy(temp_data2 + 6, result, strlen(result));
        strncpy(result, temp_data2, strlen(temp_data2));
        size = size + 3;
    }
    
    for(int i = 0; i < sizeof(result); i++){
        temp_data2[i] = 0;
        size_str[i] = 0;
    }
    
    
    //printf("Seperator is 02 \n");
    sprintf(size_str, "02");
    strncpy(temp_data2, size_str, strlen(size_str));
    strncpy(temp_data2 + 2, result, strlen(result));
    strncpy(result, temp_data2, strlen(temp_data2));
    
    return size + 1;
}

int hex_to_int(char *hexValue){
    int hexNumber;
    sscanf(hexValue, "%x", &hexNumber);
    return hexNumber;
}

void build_public_packet(public_key kp, char* final_public_packet){
    size_t separator = 2;
    char n[1024];
    char e[1024];
    size_t n_len = 0;
    size_t e_len = 0;
    size_t total_size = 0;
    size_t h_len = 0;
    char header[1024];
    
    for(int i = 0; i < sizeof(n); i++){
        n[i] = 0;
        e[i] = 0;
        header[i] = 0;
        final_public_packet[i] = 0;
    }
    
    
    printf("---------------Public Key in DER format-----------------\n");
    printf("Header\n");
    
    printf("Kp.n begins\n");
    printf("[%ld]",separator); printf("[%ld]", kp.modulus_size); printf("\n");
    PRINT_HEX(separator); PRINT_HEX(kp.modulus_size); printf("\n");
    printf("kp.n is [%s]\n", mpz_get_str(NULL, 16, kp.n));
    n_len = format_keys(kp.n, kp.modulus_size, n);
    printf("%s\n", n);
    total_size = total_size + n_len;
    printf("Kp.n ends\n");
    
    printf("Ku.e begins\n");
    PRINT_HEX(separator); PRINT_HEX(kp.e_size); printf("\n");
    printf("[%ld]",separator); printf("[%ld]", kp.e_size); printf("\n");
    printf("ku.e is [%s]\n", mpz_get_str(NULL, 16, kp.e));
    e_len = format_keys(kp.e, kp.e_size, e);
    printf("%s\n", e);
    total_size = total_size + e_len;
    printf("Ku.e ends\n");
    
    printf("Header begins\n");
    //For the constant characters
    total_size = total_size + 22;
    printf("Total Length is: %ld\n", total_size);
    h_len = format_public_header(total_size, header);
    printf("!!!!%s!!!!\n", header);
    total_size = total_size + h_len;
    printf("Header ends\n");
    
    printf("Total Length is: %ld\n", total_size);
    
    strcat(final_public_packet, header);
    strcat(final_public_packet, n);
    strcat(final_public_packet, e);
}

void build_private_packet(private_key ku, char* final_packet){
    
    size_t separator = 2;
    size_t total_size = 0;
    size_t h_len = 0;
    size_t v_len = 0;
    size_t n_len = 0;
    size_t e_len = 0;
    size_t d_len = 0;
    size_t p_len = 0;
    size_t q_len = 0;
    size_t exp1_len = 0;
    size_t exp2_len = 0;
    size_t coef_len = 0;
    
    char version[1024];
    char n[1024];
    char e[1024];
    char d[1024];
    char p[1024];
    char q[1024];
    char exp1[1024];
    char exp2[1024];
    char coef[1024];
    char header[1024];
    
    for(int i = 0; i < sizeof(version); i++){
        version[i] = 0;
        n[i] = 0;
        e[i] = 0;
        d[i] = 0;
        p[i] = 0;
        q[i] = 0;
        exp1[i] = 0;
        exp2[i] = 0;
        coef[i] = 0;
        header[i] = 0;
    }
    
    for(int i = 0; i < sizeof(final_packet); i++){
        final_packet[i] = 0;
    }
    
    
    printf("---------------Private Key in DER format-----------------\n");
    printf("Header\n");
    
    printf("Ku.version begins\n");
    printf("[%ld]",separator); printf("[%ld]", ku.version_size); printf("\n");
    PRINT_HEX(separator); PRINT_HEX(ku.version_size); printf("\n");
    
    v_len = format_keys(ku.version, ku.version_size, version);
    printf("%s\n", version);
    total_size = total_size + v_len;
    printf("Ku.version ends\n");
    
    printf("Ku.n begins\n");
    printf("[%ld]",separator); printf("[%ld]", ku.modulus_size); printf("\n");
    PRINT_HEX(separator); PRINT_HEX(ku.modulus_size); printf("\n");
    printf("ku.n is [%s]\n", mpz_get_str(NULL, 16, ku.n));
    n_len = format_keys(ku.n, ku.modulus_size, n);
    printf("%s\n", n);
    total_size = total_size + n_len;
    printf("Ku.n ends\n");
    
    printf("Ku.e begins\n");
    PRINT_HEX(separator); PRINT_HEX(ku.e_size); printf("\n");
    printf("[%ld]",separator); printf("[%ld]", ku.e_size); printf("\n");
    printf("ku.e is [%s]\n", mpz_get_str(NULL, 16, ku.e));
    e_len = format_keys(ku.e, ku.e_size, e);
    printf("%s\n", e);
    total_size = total_size + e_len;
    printf("Ku.e ends\n");
    
    printf("Ku.d begins\n");
    PRINT_HEX(separator); PRINT_HEX(ku.d_size); printf("\n");
    printf("[%ld]",separator); printf("[%ld]", ku.d_size); printf("\n");
    printf("ku.d is [%s]\n", mpz_get_str(NULL, 16, ku.d));
    d_len = format_keys(ku.d, ku.d_size, d);
    printf("%s\n", d);
    total_size = total_size + d_len;
    printf("Ku.d ends\n");
    
    printf("Ku.p begins\n");
    PRINT_HEX(separator); PRINT_HEX(ku.p_size); printf("\n");
    printf("[%ld]",separator); printf("[%ld]", ku.p_size); printf("\n");
    printf("ku.p is [%s]\n", mpz_get_str(NULL, 16, ku.p)) ;
    p_len = format_keys(ku.p, ku.p_size, p);
    printf("%s\n", p);
    total_size = total_size + p_len;
    printf("Ku.p ends\n");
    
    printf("Ku.q begins\n");
    PRINT_HEX(separator); PRINT_HEX(ku.q_size); printf("\n");
    printf("[%ld]",separator); printf("[%ld]", ku.q_size); printf("\n");
    printf("ku.q is [%s]\n", mpz_get_str(NULL, 16, ku.q));
    q_len = format_keys(ku.q, ku.q_size, q);
    printf("%s\n", q);
    total_size = total_size + q_len;
    printf("Ku.q ends\n");
    
    printf("Ku.exp1 begins\n");
    PRINT_HEX(separator); PRINT_HEX(ku.exp1_size); printf("\n");
    printf("[%ld]",separator); printf("[%ld]", ku.exp1_size); printf("\n");
    printf("ku.d_mod_p_1 is [%s]\n", mpz_get_str(NULL, 16, ku.d_mod_p_1));
    exp1_len = format_keys(ku.d_mod_p_1, ku.exp1_size, exp1);
    printf("%s\n", exp1);
    total_size = total_size + exp1_len;
    printf("Ku.exp1 ends\n");
    
    printf("Ku.exp2 begins\n");
    PRINT_HEX(separator); PRINT_HEX(ku.exp2_size); printf("\n");
    printf("[%ld]",separator); printf("[%ld]", ku.exp2_size); printf("\n");
    printf("ku.d_mod_q_1 is [%s]\n", mpz_get_str(NULL, 16, ku.d_mod_q_1));
    exp2_len = format_keys(ku.d_mod_q_1, ku.exp2_size, exp2);
    printf("%s\n", exp2);
    total_size = total_size + exp2_len;
    printf("Ku.exp2 ends\n");
    
    printf("Ku.co-ef begins\n");
    PRINT_HEX(separator); PRINT_HEX(ku.co_ef_size); printf("\n");
    printf("[%ld]",separator); printf("[%ld]", ku.co_ef_size); printf("\n");
    printf("ku.co_ef is [%s]\n", mpz_get_str(NULL, 16, ku.co_ef));
    coef_len = format_keys(ku.co_ef, ku.co_ef_size, coef);
    printf("%s\n", coef);
    total_size = total_size + coef_len;
    printf("Ku.coef ends\n");
    
    printf("Header begins\n");
    printf("Total Length is: %ld\n", total_size);
    h_len = format_private_header(total_size, header);
    printf("%s\n", header);
    total_size = total_size + h_len;
    printf("Header ends\n");
    
    printf("Total Length is: %ld\n", total_size);
    
    strcat(final_packet, header);
    strcat(final_packet, version);
    strcat(final_packet, n);
    strcat(final_packet, e);
    strcat(final_packet, d);
    strcat(final_packet, p);
    strcat(final_packet, q);
    strcat(final_packet, exp1);
    strcat(final_packet, exp2);
    strcat(final_packet, coef);
    
    //printf("%s\n", final_packet);
}

size_t break_string_sequence(unsigned char* input_der, size_t input_size, size_t starting_index, uint8_t sequence,
                             uint8_t next_sequence, decode_format *result, int value_required){
    
    unsigned char temp[2048];
    
    for(int i = 0; i < sizeof(temp); i++){
        temp[i] = 0;
    }
    
    for(int i = 0; i < input_size; i++){
        temp[i] = input_der[i];
        //printf("%.02x ", temp[i]);
    }
    printf("\n");
    
    //printf("Value at Starting index: %ld is %.02x\n", starting_index, temp[starting_index]);
    //printf("Value at Starting index + 1: %ld is %.02x\n", starting_index + 1, temp[starting_index + 1]);
    
    /*
     printf("%.02x\n", temp[starting_index]);
     printf("%.02x\n", temp[starting_index + 1]);
     */
    
    result->seperator = temp[starting_index];
    result->length_indicator = (size_t)temp[starting_index + 1];
    
    //Now points to length or length indicator
    starting_index = starting_index + 1;
    
    if(result->length_indicator <= 0x80){
        //printf("When Length is <= 0x80\n");
        result->length = (size_t)result->length_indicator;
        //Now points to data
        starting_index = starting_index + 1;
    }
    else if(result->length_indicator > 128 && result->length_indicator <= 256){
        
        if(result->length_indicator == 0x81){
            //printf("When Length is 81\n");
            result->length = (size_t)temp[starting_index + 1];
            //Now points to data
            starting_index = starting_index + 2;
        }
        else if(result->length_indicator == 0x82){
            //printf("When Length is 82\n");
            char *tmp = (char*)malloc(4);
            sprintf(tmp, "%.02x%.02x\n", temp[starting_index + 1], temp[starting_index + 2]);
            result->length = hex_to_int(tmp);
            //printf("%ld\n", result->length);
            /*IGNORED FOR NOW*/
            //Now points to data
            starting_index = starting_index + 3;
        }
    }
    else if(result->length_indicator > 256){
        /*
         result->length[0] = temp[starting_index];
         result->length[1] = temp[starting_index + 1];
         */
        //Now points to data
        starting_index = starting_index + 4;
    }
    
    //printf("Starting index before reading or not reading data: %ld\n", starting_index);
    
    if(value_required == VALUE_REQUIRED){
        //Adjust starting index appropriately
        for(size_t j = 0; j < result->length; j++){
            result->value[j] = temp[starting_index];
            starting_index = starting_index + 1;
        }
        //printf("Starting index of next: %ld\n", starting_index);
        if(temp[starting_index] == next_sequence){
            //printf("Things are proper when value is required\n");
        }
        else{
            printf("ERROR!!\n");
        }
    }
    else if(value_required == VALUE_NOT_REQUIRED){
        //printf("Starting index of next: %ld\n", starting_index);
        if(temp[starting_index] == next_sequence){
            //printf("Things are proper when value not required\n");
        }
        else{
            printf("ERROR!!\n");
        }
        return starting_index;
    }
    
    
    return starting_index;
}

void read_public_der(FILE* fp, public_key* kp_decoded){
    
    decode_format header;
    decode_format n;
    decode_format e;
    
    size_t next_index = 0;
    
    size_t lSize;
    size_t read_bytes;
    
    if(fp == NULL){
        printf("ERROR!\n");
    }
    
    unsigned char *input_der;
    
    fseek (fp , 0 , SEEK_END);
    lSize = ftell (fp);
    rewind (fp);
    
    printf("%ld\n", lSize);
    input_der = (unsigned char*) malloc (sizeof(unsigned char)*lSize);
    
    read_bytes = fread(input_der, 1, lSize, fp);
    
    for(int i = 0; i < lSize; i++){
        printf("%.02x ", input_der[i]);
    }
    printf("\n");
    
    next_index = break_string_sequence(input_der, lSize, 0, 0x30, 0x30, &header, VALUE_NOT_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("Header: %.02x %.02lx %.04lx\n", header.seperator, header.length_indicator, header.length);
    
    
    decode_format temp;
    next_index = break_string_sequence(input_der , lSize, next_index, 0x30, 0x03, &temp, VALUE_REQUIRED);
    
    
    
    next_index = break_string_sequence(input_der, lSize, 25, 0x02, 0x02, &n, VALUE_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("n: %.02x %.02lx %.02lx\n", n.seperator, n.length_indicator, n.length);
    mpz_import(kp_decoded->n, n.length, 1, 1, 0, 0, n.value);
    kp_decoded->modulus_size = n.length;
    printf("ku.n is [%s]\n", mpz_get_str(NULL, 16, kp_decoded->n));
    printf("\n");
    
    
    next_index = break_string_sequence(input_der, lSize, next_index, 0x02, 0x00, &e, VALUE_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("e: %.02x %.02lx %.02lx\n", e.seperator, e.length_indicator, e.length);
    mpz_import(kp_decoded->e, e.length, 1, 1, 0, 0, e.value);
    kp_decoded->e_size = e.length;
    printf("ku.e is [%s]\n", mpz_get_str(NULL, 16, kp_decoded->e));
    printf("\n");
    
    kp_decoded->modulus_size = strlen(mpz_get_str(NULL, 16, kp_decoded->n)) / 2;
    kp_decoded->e_size = strlen(mpz_get_str(NULL, 16, kp_decoded->e)) / 2;
    
}

void read_private_der(FILE* fp, private_key* ku_decoded){
    
    decode_format header;
    decode_format version;
    decode_format n;
    decode_format e;
    decode_format d;
    decode_format p;
    decode_format q;
    decode_format exp1;
    decode_format exp2;
    decode_format coef;
    size_t next_index = 0;
    
    size_t lSize;
    size_t read_bytes;
    
    if(fp == NULL){
        printf("ERROR!\n");
    }
    unsigned char *input_der;
    
    fseek (fp , 0 , SEEK_END);
    lSize = ftell (fp);
    rewind (fp);
    
    printf("%ld\n", lSize);
    input_der = (unsigned char*) malloc (sizeof(unsigned char)*lSize);
    
    read_bytes = fread(input_der, 1, lSize, fp);
    
    for(int i = 0; i < lSize; i++){
        printf("%.02x ", input_der[i]);
    }
    printf("\n");
    
    next_index = break_string_sequence(input_der, lSize, 0, 0x30, 0x02, &header, VALUE_NOT_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("Header: %.02x %.02lx %.04lx\n", header.seperator, header.length_indicator, header.length);
    
    next_index = break_string_sequence(input_der, lSize, next_index, 0x02, 0x02, &version, VALUE_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("Version: %.02x %.02lx %.02lx\n", version.seperator, version.length_indicator, version.length);
    mpz_import(ku_decoded->version, version.length, 1, 1, 0, 0, version.value);
    printf("ku.version is [%s]\n", mpz_get_str(NULL, 16, ku_decoded->version));
    printf("\n");
    
    next_index = break_string_sequence(input_der, lSize, next_index, 0x02, 0x02, &n, VALUE_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("n: %.02x %.02lx %.02lx\n", n.seperator, n.length_indicator, n.length);
    mpz_import(ku_decoded->n, n.length, 1, 1, 0, 0, n.value);
    printf("ku.n is [%s]\n", mpz_get_str(NULL, 16, ku_decoded->n));
    printf("\n");
    
    
    next_index = break_string_sequence(input_der, lSize, next_index, 0x02, 0x02, &e, VALUE_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("e: %.02x %.02lx %.02lx\n", e.seperator, e.length_indicator, e.length);
    mpz_import(ku_decoded->e, e.length, 1, 1, 0, 0, e.value);
    printf("ku.e is [%s]\n", mpz_get_str(NULL, 16, ku_decoded->e));
    printf("\n");
    
    next_index = break_string_sequence(input_der, lSize, next_index, 0x02, 0x02, &d, VALUE_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("d: %.02x %.02lx %.02lx\n", d.seperator, d.length_indicator, d.length);
    mpz_import(ku_decoded->d, d.length, 1, 1, 0, 0, d.value);
    printf("ku.d is [%s]\n", mpz_get_str(NULL, 16, ku_decoded->d));
    printf("\n");
    
    next_index = break_string_sequence(input_der, lSize, next_index, 0x02, 0x02, &p, VALUE_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("p: %.02x %.02lx %.02lx\n", p.seperator, p.length_indicator, p.length);
    mpz_import(ku_decoded->p, p.length, 1, 1, 0, 0, p.value);
    printf("ku.p is [%s]\n", mpz_get_str(NULL, 16, ku_decoded->p));
    printf("\n");
    
    next_index = break_string_sequence(input_der, lSize, next_index, 0x02, 0x02, &q, VALUE_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("q: %.02x %.02lx %.02lx\n", q.seperator, q.length_indicator, q.length);
    mpz_import(ku_decoded->q, q.length, 1, 1, 0, 0, q.value);
    printf("ku.q is [%s]\n", mpz_get_str(NULL, 16, ku_decoded->q));
    printf("\n");
    
    next_index = break_string_sequence(input_der, lSize, next_index, 0x02, 0x02, &exp1, VALUE_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("exp1: %.02x %.02lx %.02lx\n", exp1.seperator, exp1.length_indicator, exp1.length);
    mpz_import(ku_decoded->d_mod_p_1, exp1.length, 1, 1, 0, 0, exp1.value);
    printf("ku.exp1 is [%s]\n", mpz_get_str(NULL, 16, ku_decoded->d_mod_p_1));
    printf("\n");
    
    next_index = break_string_sequence(input_der, lSize, next_index, 0x02, 0x02, &exp2, VALUE_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("exp2: %.02x %.02lx %.02lx\n", exp2.seperator, exp2.length_indicator, exp2.length);
    mpz_import(ku_decoded->d_mod_q_1, exp2.length, 1, 1, 0, 0, exp2.value);
    printf("ku.exp2 is [%s]\n", mpz_get_str(NULL, 16, ku_decoded->d_mod_q_1));
    printf("\n");
    
    next_index = break_string_sequence(input_der, lSize, next_index, 0x02, 0x00, &coef, VALUE_REQUIRED);
    printf("Next Index: %ld\n", next_index);
    printf("Coef: %.02x %.02lx %.02lx\n", coef.seperator, coef.length_indicator, coef.length);
    mpz_import(ku_decoded->co_ef, coef.length, 1, 1, 0, 0, coef.value);
    printf("ku.coef is [%s]\n", mpz_get_str(NULL, 16, ku_decoded->co_ef));
    printf("\n");
    
    ku_decoded->version_size = strlen(mpz_get_str(NULL, 16, ku_decoded->version)) / 2;
    ku_decoded->modulus_size = strlen(mpz_get_str(NULL, 16, ku_decoded->n)) / 2;
    ku_decoded->e_size = strlen(mpz_get_str(NULL, 16, ku_decoded->e)) / 2;
    ku_decoded->d_size = strlen(mpz_get_str(NULL, 16, ku_decoded->d)) / 2;
    ku_decoded->p_size = strlen(mpz_get_str(NULL, 16, ku_decoded->p)) / 2;
    ku_decoded->q_size = strlen(mpz_get_str(NULL, 16, ku_decoded->q)) / 2;
    ku_decoded->exp1_size = strlen(mpz_get_str(NULL, 16, ku_decoded->d_mod_p_1)) / 2;
    ku_decoded->exp2_size = strlen(mpz_get_str(NULL, 16, ku_decoded->d_mod_q_1)) / 2;
    ku_decoded->co_ef_size = strlen(mpz_get_str(NULL, 16, ku_decoded->co_ef)) / 2;
    
    fclose(fp);
    
}

unsigned char generate_random_octet(){
	/*
    unsigned char your_buffer;
    
    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, &your_buffer, sizeof(unsigned char));
    close(fd);
    
    if (your_buffer == 0)
        your_buffer = your_buffer | 0xFF;
    */
    return '1';
}
