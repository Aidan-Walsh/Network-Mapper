#!/bin/bash
for i in $(seq $2 $3) ;do (ping -c 1 $1.$i | grep "bytes from" &)  1>scan.txt ;done