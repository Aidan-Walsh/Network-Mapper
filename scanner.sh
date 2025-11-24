#!/bin/bash
nmap -sP --max-retries=1 --host-timeout=100ms $1.$2-$3 | grep $1