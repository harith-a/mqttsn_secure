#!/bin/bash

I="\
123456781234567812345678123456781234567812345678\
123456781234567812345678123456781234567812345678\
123456781234567812345678123456781234567812345678\
123456781234567812345678123456781234567812345678\
12345678123456781234567812345678123456781234567"
    
    
II="\
123456781234567812345678123456781234567812345678\
123456781234567812345678123456781234567812345678\
123456781234567812345678123456781234567812345678\
123456781234567812345678123456781234567812345678\
1234567812345678123456781234567"
    
./mqtt-sn-pubs -p 1884 -h 10.8.132.36 -t ha -q 0 -m $I -e kln
#./mqtt-sn-pubs -p 1884 -h 10.8.132.36 -t ha -q 0 -m $II -e aes -L
