#!/bin/bash
source common.sh

# Generate primary key
tpm2_createprimary -C p -g sha256 -G ecc -c primary.ctx
# Create policy from current SHA1 PCR0,1,2,3 values
tpm2_createpolicy --policy-pcr -l "sha1:0,1,2,3" -L policy.dat
# Create signing key, only usable when PCRs match above policy
tpm2_create -C primary.ctx -G ecc -a 'sign|fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy' -L policy.dat -c sign.ctx

# Make keys persistent
tpm2_evictcontrol -C p -c primary.ctx -o primary.handle
tpm2_evictcontrol -C p -c sign.ctx -o sign.handle

# Make NVRAM index to store signature
tpm2_nvdefine -C p -s $NVRAM_INDEX_SIZE -a "ownerread|ppwrite|platformcreate|write_stclear|read_stclear" $NVRAM_INDEX
