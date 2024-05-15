# Given a TPMS_ATTEST evidence packet (generated from tpm2_NVCertify), check that the provided nonce matches the nonce in the evidence and that the hash in the evidence matches the hash provided
def _parse_and_check_tpms_attest_cert(self, evidence:bytes, provided_nonce:bytes, calculated_hash:str) -> bool:
    magic_start = 0
    magic_size = 4
    magic: str = evidence[magic_start:magic_start+magic_size].hex()
    print("magic:", magic)
    if magic != "ff544347":
        print("magic fail")
        return False
    
    attestation_type_start = magic_start+magic_size
    attestation_type_size = 2
    attestation_type: str = evidence[attestation_type_start:attestation_type_start+attestation_type_size].hex()
    print("attestation_type:", attestation_type)
    if attestation_type != "8014": # NVRAM Certify type
        print("attestation_type fail")
        return False
    
    signing_key_name_size_start = attestation_type_start+attestation_type_size
    signing_key_name_size_size = 2
    signing_key_name_size: int = int.from_bytes(evidence[signing_key_name_size_start:signing_key_name_size_start+signing_key_name_size_size], "big")
    print("signing_key_name_size:", signing_key_name_size)
    signing_key_name_start = signing_key_name_size_start+signing_key_name_size_size
    signing_key_name = evidence[signing_key_name_start:signing_key_name_start+signing_key_name_size]
    print("signing_key_name:", signing_key_name.hex())
    
    nonce_size_start = signing_key_name_start+signing_key_name_size
    nonce_size_size = 2
    nonce_size: int = int.from_bytes(evidence[nonce_size_start:nonce_size_start+nonce_size_size], "big")
    print("nonce_size:", nonce_size)
    nonce_start = nonce_size_start+nonce_size_size
    extracted_nonce: str = evidence[nonce_start:nonce_start+nonce_size].hex()
    print("nonce:", extracted_nonce)
    
    if extracted_nonce != provided_nonce.hex():
        print("nonce fail")
        return False
    
    clock_info_start = nonce_start+nonce_size
    clock_info_size = 8+4+4+1
    clock_info = evidence[clock_info_start:clock_info_start+clock_info_size]
    print("clock_info:", clock_info.hex())
    
    firmware_version_start = clock_info_start+clock_info_size
    firmware_version_size = 8
    firmware = evidence[firmware_version_start:firmware_version_start+firmware_version_size]
    print("firmware:", firmware.hex())
    
    nvindex_name_size_start = firmware_version_start+firmware_version_size
    nvindex_name_size_size = 2
    nvindex_name_size: int = int.from_bytes(evidence[nvindex_name_size_start:nvindex_name_size_start+nvindex_name_size_size], "big")
    print("nvindex_name_size:", nvindex_name_size)
    nvindex_name_start = nvindex_name_size_start+nvindex_name_size_size
    nvindex_name = evidence[nvindex_name_start:nvindex_name_start+nvindex_name_size]
    print("nvindex_name:", nvindex_name.hex())
    
    nvindex_offset_start = nvindex_name_start+nvindex_name_size
    nvindex_offset_size = 2
    nvindex_offset: str = evidence[nvindex_offset_start:nvindex_offset_start+nvindex_offset_size].hex()
    print("nvindex_offset:", nvindex_offset)
    if nvindex_offset != "0000":
        print("nvindex_offset fail")
        return False
    
    nvindex_contents_size_start = nvindex_offset_start+nvindex_offset_size
    nvindex_contents_size_size = 2
    nvindex_contents_size: int = int.from_bytes(evidence[nvindex_contents_size_start:nvindex_contents_size_start+nvindex_contents_size_size], "big")
    print("nvindex_contents_size:", nvindex_contents_size)
    nvindex_contents_start = nvindex_contents_size_start+nvindex_contents_size_size
    nvindex_contents: str = evidence[nvindex_contents_start:nvindex_contents_start+nvindex_contents_size].hex()
    print("nvindex_contents:", nvindex_contents)
    
    if nvindex_contents != calculated_hash:
        print("nvindex_contents fail")
        return False
    return True 
