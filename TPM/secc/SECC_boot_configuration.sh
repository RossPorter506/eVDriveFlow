#!/bin/bash
source common.sh

# Generate primary key
#tpm2_createprimary -C p -g sha256 -G ecc -c primary.ctx
# Create policy from current SHA1 PCR0,1,2,3 values
#tpm2_createpolicy --policy-pcr -l "sha1:0,1,2,3" -L policy.dat
# Create signing key, only usable when PCRs match above policy
#tpm2_create -C primary.ctx -G ecc -a 'sign|fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy' -L policy.dat -c sign.ctx

# Make keys persistent
#tpm2_evictcontrol -C p -c primary.ctx -o primary.handle
#tpm2_evictcontrol -C p -c sign.ctx -o sign.handle

# Make NVRAM index to store signature
#tpm2_nvdefine -C p -s $NVRAM_INDEX_SIZE -a "ownerread|ppwrite|platformcreate|write_stclear|read_stclear" $NVRAM_INDEX


# Write capabilities to file
# TODO
echo "12345" > secc_capabilities.dat

# Try to sign with correct PCRs:
tpm2_sign -c sign.ctx secc_capabilities.dat -p pcr:sha1:0,1,2,3 -o ecdsa_sig.der -f plain

# Convert signature from DER to P1363 format. Smaller.
python <<HEREDOC
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

signatureDER = open("ecdsa_sig.der", 'rb').read()

(r, s) = decode_dss_signature(signatureDER)
signatureP1363 = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')

open("ecdsa_sig.p1363", 'wb').write(signatureP1363)
HEREDOC

tpm2_nvwrite $NVRAM_INDEX -C p -i ecdsa_sig.p1363 # Write new value, if necessary
tpm2_nvwritelock -C p $NVRAM_INDEX # write lock until next reboot. We would additionally lock out platform too, but do this just in case.
