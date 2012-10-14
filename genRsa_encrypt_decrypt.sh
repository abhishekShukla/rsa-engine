#!/bin/sh
sudo ./main genRsa private.der private.pem public.der public.pem
sleep 3
sudo chmod 777 private.pem public.pem private.der public.der
touch temp_base64_decoded.der
touch temp_private_base64_decoded.der
sudo chmod 777 temp_base64_decoded.der temp_private_base64_decoded.der
sudo ./main encrypt public.pem plain_input cipher_text
sudo ./main decrypt private.pem cipher_text plain_output
sudo diff plain_input plain_output
