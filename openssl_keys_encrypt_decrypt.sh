#!/bin/sh
sudo openssl genrsa 1024 -out private_rsa.pem 
sudo openssl rsa -in private.pem -pubout -out public_rsa.pem
sudo ./main encrypt public_rsa.pem plain_input cipher_text 
sudo ./main decrypt private_rsa.pem cipher_text plain_output 
diff plain_input plain_output
