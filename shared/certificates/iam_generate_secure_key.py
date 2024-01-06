from ecdsa import VerifyingKey, SigningKey
import os

if __name__ == "__main__":
    try:
        os.makedirs(folder_path)
    except FileExistsError:
        # Ignore the error if the folder already exists
        pass
    secc_secure_key = SigningKey.generate()
    secc_public_key = secc_secure_key.verifying_key
    with open("IAM_keys/secc_private_attestation_key.pem", "wb") as f:
        f.write(secc_secure_key.to_pem(format="pkcs8"))
    with open("IAM_keys/secc_public_attestation_key.pem", "wb") as f:
        f.write(secc_public_key.to_pem())
