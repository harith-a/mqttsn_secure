#!/bin/bash

while true
    do
        ./mqtt-sn-pub -p 1884 -h 127.0.01 -t ha -m 19 -q 1 
		echo $(($(date +%s%N)/1000000))
		sleep 0.001
    done
