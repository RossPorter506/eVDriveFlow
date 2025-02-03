from ecdsa import VerifyingKey, SigningKey, Ed25519
import os

if __name__ == "__main__":
    try:
        os.makedirs("IAM_keys")
    except FileExistsError:
        # Ignore the error if the folder already exists
        pass
    
    # SECC
    try:
        with open("IAM_keys/IAM_TEE_key_secc.der", "rb") as f:
            print("Reading existing SECC key...")
            secc_der_string = f.read()
            secc_secure_key = SigningKey.from_der(secc_der_string)
    except FileNotFoundError:
        print("Generating new SECC key...")
        secc_secure_key = SigningKey.generate(curve=Ed25519)
        secc_secure_key_der = secc_secure_key.to_der(format="pkcs8")
        with open("IAM_keys/IAM_TEE_key_secc.der", "wb") as f:
            f.write(secc_secure_key_der)
    secc_public_key = secc_secure_key.verifying_key
    
    with open("IAM_keys/secc_private_attestation_key.pem", "wb") as f:
        f.write(secc_secure_key.to_pem(format="pkcs8"))
    with open("IAM_keys/secc_public_attestation_key.pem", "wb") as f:
        f.write(secc_public_key.to_pem())
    
    # EVCC
    try:
        with open("IAM_keys/IAM_TEE_key_evcc.der", "rb") as f:
            print("Reading existing EVCC key...")
            evcc_der_string = f.read()
            evcc_secure_key = SigningKey.from_der(evcc_der_string)
    except FileNotFoundError:
        print("Generating new EVCC key...")
        evcc_secure_key = SigningKey.generate(curve=Ed25519)
        evcc_secure_key_der = evcc_secure_key.to_der(format="pkcs8")
        with open("IAM_keys/IAM_TEE_key_evcc.der", "wb") as f:
            f.write(evcc_secure_key_der)
    evcc_public_key = evcc_secure_key.verifying_key
    
    with open("IAM_keys/evcc_private_attestation_key.pem", "wb") as f:
        f.write(evcc_secure_key.to_pem(format="pkcs8"))
    with open("IAM_keys/evcc_public_attestation_key.pem", "wb") as f:
        f.write(evcc_public_key.to_pem())
