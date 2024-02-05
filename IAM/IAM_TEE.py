from hashlib import sha256
import subprocess, os

# TEE code for performing software/firmware measurement 

# Get hash of files in current working directory. Because of how the project is run, this is 
# the location of the evse_gui.py file, which is ../secc and ../malicious_secc, respectively
def hash_sign_secc_software(nonce: int) -> (bytes, bytes):
    result_bytes: str = subprocess.check_output(f"""sudo /usr/bin/digest_sign-rs "{os.getcwd()}" {nonce}""", shell=True)
    (resultOK, hsh_str, sig_str) = result_bytes.decode("utf-8").split(',')
    if int(resultOK) == 0:
        raise RuntimeError("Error in secure world")
    return (bytes.fromhex(hsh_str), bytes.fromhex(sig_str))

# Generate 'reference' hash for EVCC to use.
if __name__ == "__main__":
    # Make sure we measure the code in the ../secc folder.
    os.chdir(os.path.join( os.path.dirname(__file__), os.path.pardir, "secc"))

    (hsh, _) = hash_sign_secc_software(0)

    os.chdir(os.path.join(os.path.pardir, "IAM"))

    with open("secc.sha256", "wb") as f:
        f.write(hsh)
