#!/bin/bash
source common.sh

# Service ID, Hash.
# As calculated in evse_dummy_controller._calc_service_hashes
# 6, 456e76cf449c73d8dd0580c3e8dfd41208fca476a9fa34831dd9c2e35a72c855
# 46483, 27841c9ffed7ba0a406e784ba48fcc87eb091e3c62cd7018f8bcb16db68bc031
# 46484, b743ef01d97cf3bda9da8be44c14df2aa90de92e535f6f28e067b28aa25b47f2
# Write capabilities to file.
python <<HEREDOC
services = bytearray(int(2).to_bytes(2, 'big'))
services += bytearray.from_hex("456e76cf449c73d8dd0580c3e8dfd41208fca476a9fa34831dd9c2e35a72c855")

services += bytearray(int(46483).to_bytes(2, 'big'))
services += bytearray.from_hex("27841c9ffed7ba0a406e784ba48fcc87eb091e3c62cd7018f8bcb16db68bc031")

services += bytearray(int(46484).to_bytes(2, 'big'))
services += bytearray.from_hex("b743ef01d97cf3bda9da8be44c14df2aa90de92e535f6f28e067b28aa25b47f2")

open("secc_evidence.dat", 'wb').write(services)
HEREDOC

tpm2_hash -C p -g sha256 -o secc_evidence_hash.sha256 secc_evidence.dat

tpm2_nvwrite $NVRAM_INDEX -C p -i secc_evidence_hash.sha256 # Write new value to index
tpm2_nvwritelock -C p $NVRAM_INDEX # write lock until next reboot. We would additionally lock out platform too, but do this just in case.
