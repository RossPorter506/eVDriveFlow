#!/bin/bash
source common.sh

# $1 Should contain a hex-encoded nonce, e.g. 'f2b4ca1f032'

tpm2_nvcertify -C sign.handle -c o -g sha256 -s ecc -f plain -o sig -q $1 --attestation attestation.nv_cert_info -o ecc_signature.der $NVRAM_INDEX
