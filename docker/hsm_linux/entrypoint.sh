#!/bin/bash

# Get configured slot
export SLOT_ID=$(cat /slot.txt)
# Run command and capture output (negotiation error expected)
python3.11 hsm_validate.py > command_output.txt 2>&1
pcregrep 'AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE' command_output.txt > /dev/null 2>&1
if [ $? -eq 0 ]; then
    exit 0
else
    cat command_output.txt
    exit 1
fi
