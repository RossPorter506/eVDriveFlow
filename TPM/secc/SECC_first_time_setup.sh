#!/bin/bash
THISDIR=$(dirname $0)
source ${THISDIR}/common.sh

# Generate primary key
tpm2_createprimary -C p -g sha256 -G ecc -c ${THISDIR}/pprimary.ctx
tpm2_createprimary -C o -g sha256 -G ecc -c ${THISDIR}/oprimary.ctx
# Create policy from current SHA1 PCR0,1,2,3 values
tpm2_createpolicy --policy-pcr -l "sha1:0,1,2,3" -L ${THISDIR}/policy.dat
# Create signing key, only usable when PCRs match above policy
tpm2_create -C o -G ecc -a 'sign|fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|userwithauth' -L ${THISDIR}/policy.dat -c ${THISDIR}/sign.ctx -p pass

# Make keys persistent
tpm2_evictcontrol -C p -c ${THISDIR}/pprimary.ctx -o ${THISDIR}/pprimary.handle
tpm2_evictcontrol -C o -c ${THISDIR}/oprimary.ctx -o ${THISDIR}/oprimary.handle
tpm2_evictcontrol -C o -c ${THISDIR}/sign.ctx -o ${THISDIR}/sign.handle

tpm2_readpublic -c ${THISDIR}/sign.handle -f pem -o ${THISDIR}/secc_sign_public_key.pem

# Make NVRAM index to store signature
tpm2_nvdefine -C p -s $NVRAM_INDEX_SIZE -a "ownerread|ppwrite|platformcreate|write_stclear|read_stclear" $NVRAM_INDEX
#tpm2_nvundefine -C p $NVRAM_INDEX
