#!/bin/bash
THISDIR=$(dirname $0)
source ${THISDIR}"/common.sh"

# $1 Should contain a hex-encoded nonce, e.g. 'f2b4ca1f032'

tpm2_nvcertify -C ${THISDIR}/sign.handle -P pass -c o -g sha256 -s ecdsa -f plain -o sig -q $1 --attestation ${THISDIR}/attestation.nv_cert_info -o ${THISDIR}/ecc_signature.der $NVRAM_INDEX
