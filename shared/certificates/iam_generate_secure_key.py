from ecdsa import VerifyingKey, SigningKey

if __name__ == "__main__":
    secc_secure_key = SigningKey.generate()
    secc_public_key = secc_secure_key.verifying_key
    with open("IAM_keys/secc_secure_key.pem", "wb") as f:
        f.write(secc_secure_key.to_pem(format="pkcs8"))
    with open("IAM_keys/secc_public_key.pem", "wb") as f:
        f.write(secc_public_key.to_pem())
