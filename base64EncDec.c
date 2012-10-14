//
//  base64EncDec.c
//  rsa_engine
//
//  Created by Abhishek Shukla Ravishankara on 10/8/12.
//  Copyright (c) 2012 Abhishek Shukla Ravishankara. All rights reserved.
//

#include "rsa.h"

int base64encode(const void* data_buf, size_t dataLength, char* result){
    
    /* Base 64 Encoder Table */
    const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    const unsigned char *data = (const unsigned char *)data_buf;
    
    size_t resultIndex = 0;
    
    /* If the output needs to be padded on the end */
    int pad_count = dataLength % 3;
    
    /* For the four 6 bits */
    uint8_t n0, n1, n2, n3;
    
    /* For the 24 bits to be considered */
    uint32_t n = 0;
    uint32_t n_1 = 0;
    uint32_t n_2 = 0;
    uint32_t n_3 = 0;
    
    /* Take three characters at a time */
    for(size_t x = 0; x < dataLength; x += 3){
        
        n_1 = 0;
        n_2 = 0;
        n_3 = 0;
        n = 0;
        n0 = 0;
        n1 = 0;
        n2 = 0;
        n3 = 0;
        
        /* since n is a 32 bit number, the 8 bits data have to be moved by 16 places (first 8 bits will always be 0) */
        n_1 = data[x] << 16;
        
        /* if condition so that overflow does not occur */
        if((x+1) < dataLength){
            n_2 = data[x+1] << 8;
        }
        
        /* if condition so that overflow does not occur */
        if((x+2) < dataLength){
            n_3 = data[x+2];
        }
        
        n = n_1 + n_2 + n_3;
        
        /* Now splitting the n into 6, 6 bit numbers */
        
        /* Ex: n0 = by shiting the 24 digit number 18 times, in n0 will comprise of two
         unimportant bits followed by required 6 bits. Thus anding the 63 (111111) is important
         Same for others likewise. Anding by 63 basically ignores the two msb binary digits*/
        
        n0 = (uint8_t)(n >> 18) & 63;
        n1 = (uint8_t)(n >> 12) & 63;
        n2 = (uint8_t)(n >> 6) & 63;
        n3 = (uint8_t)n & 63;
        
        /* if data is 8 bits, it will result in two characters in base64Encoding */
        
        /* First base64encoded character */
        /*
        if((resultIndex % 76) == 0  && resultIndex != 0){
            result[resultIndex++] = '\r';
            result[resultIndex++] = '\n';
            
        }
         */
        result[resultIndex++] = base64chars[n0];
        /*
        if((resultIndex % 76) == 0  && resultIndex != 0){
            result[resultIndex++] = '\r';
            result[resultIndex++] = '\n';
            
        }
         */
        /* Second base64encoded character */
        result[resultIndex++] = base64chars[n1];
        /*
        if((resultIndex % 76) == 0  && resultIndex != 0){
            result[resultIndex++] = '\r';
            result[resultIndex++] = '\n';
            
        }
         */
        
        /* if data is 16 bits, it will result in three characters in base64Encoding */
        
        /* To make sure you dont encode zeroes if there were no characters since n was initialized to 0 */
        if((x+1) < dataLength){
            /* This base64Encoded character */
            result[resultIndex++] = base64chars[n2];
            
        }
        
        if((resultIndex % 76) == 0  && resultIndex != 0){
            result[resultIndex++] = '\r';
            result[resultIndex++] = '\n';
            
        }
        /* if data is 24 bits, it will result in four characters in base64Encoding */
        
        /* To make sure you dont encode zeroes if there were no characters since n was initialized to 0 */
        if((x+2) < dataLength){
            
            /* This base64Encoded character */
            result[resultIndex++] = base64chars[n3];
            
        }
        
    }
    
    /* Now after encoding, we need to adding padding data if necessary */
    
    if (pad_count > 0)
    {
        for (; pad_count < 3; pad_count++)
        {
            result[resultIndex++] = '=';
        }
    }
    
    /* Null terminated string */    
    result[resultIndex] = 0;
    
    /* success */
    return 0;
}

int base64decode(const void* data_buf, size_t dataLength, unsigned char* result){
    
    const char *data = (const char *)data_buf;
    
    /* Base 64 Encoder Table */
    const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    /* Base 64 decoder table */
    uint8_t base64decodertable[256];
    
    int resultIndex = 0;
    
    /* For the four 6 bits */
    uint32_t n0 = 0;
    uint32_t n1 = 0;
    uint32_t n2 = 0;
    uint32_t n3 = 0;
    
    /* For the 24 bits to be considered */
    uint32_t n = 0;
    
    /* For the output characters */
    uint8_t d0, d1, d2;
    
    for (int i = 0; i < 256; i++){
        base64decodertable[i] = 0;
    }
    
    /* build decoder table */
    for (int i = 0; i < 0x40; i++){
        base64decodertable[(uint8_t)base64chars[i]] = i;
    }
    
    
    /* check if encoded data is proper */
    if(dataLength % 4 != 0){
        return -1;
    }
    
    /* take 4 characters at a time */
    for(int x = 0; x < dataLength; x += 4){
        
        n0 = 0;
        n1 = 0;
        n2 = 0;
        n3 = 0;
        n = 0;
        d0 = 0;
        d1 = 0;
        d2 = 0;
        
        if(data[x] == '\r'){
            x++;
        }
        
        if(data[x] == '\n'){
            x++;
        }
        
        /* First Six Bits */
        n0 = (base64decodertable[data[x]]) << 18;
        
        /* if condition so that overflow does not occur */
        if((x+1) < dataLength){
            n1 = (base64decodertable[data[x + 1]]) << 12;
        }
        
        /* if condition so that overflow does not occur */
        if((x+2) < dataLength){
            n2 = (base64decodertable[data[x + 2]]) << 6;
        }
        
        /* if condition so that overflow does not occur */
        if((x+3) < dataLength){
            n3 = (base64decodertable[data[x + 3]]);
        }
        
        /* constructing n */
        n = n0 + n1 + n2 + n3;
        
        /* Extracting First 8 bits out of the 24 bits */
        d0 = (uint8_t)(n >> 16) & 255;
        
        /* Extracting Second 8 bits out of the 24 bits */
        d1 = (uint8_t)(n >> 8) & 255;
        
        /* Extracting Third 8 bits out of the 24 bits */
        d2 = (uint8_t)n & 255;
        
        /* First Character */
        result[resultIndex++] = d0;
        
        /* Second Character */
        result[resultIndex++] = d1;
        
        /* Third Character */
        result[resultIndex++] = d2;
        
    }
    
    if(data[dataLength - 1] == '='){
        resultIndex = resultIndex - 1;
    }
    
    if(data[dataLength - 2] == '='){
        resultIndex = resultIndex - 1;
    }
    
    /* Null terminated string */
    result[resultIndex] = '\0';
    
    
    /* success */
    return resultIndex;
}
