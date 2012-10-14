#!/bin/sh
sudo ./main genRsa private.der private.pem public.der public.pem
sleep 3
sudo chmod 777 private.pem public.pem private.der public.der
c
sudo chmod 777 public_rsa.pem
sudo diff public.pem public_rsa.pem
