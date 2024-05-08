#!/bin/bash
source common.sh

tpm2_nvread -C o $NVRAM_INDEX
