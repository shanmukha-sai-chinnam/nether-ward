#!/bin/bash
# Sensitive credential reconnaissance sample
cat /etc/passwd | cut -d: -f1
cat /etc/shadow | grep -v '*'
