#!/bin/bash
for i in $(seq $2 $3) ;do (ping -c 1 $1.$i | grep "bytes from" &) 2>/dev/null ;done