#!/bin/bash
source common.sh

# Generate primary key
tpm2_createprimary -C p -g sha256 -G ecc -c pprimary.ctx
tpm2_createprimary -C o -g sha256 -G ecc -c oprimary.ctx
# Create policy from current SHA1 PCR0,1,2,3 values
tpm2_createpolicy --policy-pcr -l "sha1:0,1,2,3" -L policy.dat
# Create signing key, only usable when PCRs match above policy
tpm2_create -C o -G ecc -a 'sign|fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|userwithauth' -L policy.dat -c sign.ctx -p pass

# Make keys persistent
tpm2_evictcontrol -C p -c pprimary.ctx -o pprimary.handle
tpm2_evictcontrol -C o -c oprimary.ctx -o oprimary.handle
tpm2_evictcontrol -C o -c sign.ctx -o sign.handle

tpm2_readpublic -c sign.handle -f pem -o secc_sign_public_key.pem

# Make NVRAM index to store signature
tpm2_nvdefine -C p -s $NVRAM_INDEX_SIZE -a "ownerread|ppwrite|platformcreate|write_stclear|read_stclear" $NVRAM_INDEX
