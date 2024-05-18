#!/bin/bash
THISDIR=$(dirname $0)
source ${THISDIR}"/common.sh"

# Write capabilities to file. Realistically these could already be hashes.
python <<HEREDOC
# Supported services:
# 2,6,46483,46484
supported_services = bytearray(int(2).to_bytes(2, 'big'))
supported_services += int(6).to_bytes(2, 'big')
supported_services += int(46483).to_bytes(2, 'big')
supported_services += int(46484).to_bytes(2, 'big')

# Mandatory if Mutually Supported services
# 46484
MiMS_services = bytearray(int(46484).to_bytes(2, 'big'))

# Supported App Protocols
# "urn:iso:std:iso:15118:-20:DC", major=1, minor=0
# "urn:iso:std:iso:15118:-20:TPM" major=1, minor=0
supported_app_protocols = bytearray("urn:iso:std:iso:15118:-20:DC".encode("UTF-8"))
supported_app_protocols += int(1).to_bytes(4, 'big')
supported_app_protocols += int(0).to_bytes(4, 'big')

supported_app_protocols += bytearray("urn:iso:std:iso:15118:-20:TPM".encode("UTF-8"))
supported_app_protocols += int(1).to_bytes(4, 'big')
supported_app_protocols += int(0).to_bytes(4, 'big')

evidence = supported_services + MiMS_services + supported_app_protocols
open("${THISDIR}/evcc_evidence.dat", 'wb').write(evidence)
HEREDOC

tpm2_hash -C p -g sha256 -o ${THISDIR}/evcc_evidence_hash.sha256 ${THISDIR}/evcc_evidence.dat

tpm2_nvwrite $NVRAM_INDEX -C p -i ${THISDIR}/evcc_evidence_hash.sha256 # Write new value to index
tpm2_nvwritelock -C p $NVRAM_INDEX # write lock until next reboot. We would additionally lock out platform too, but do this just in case.
