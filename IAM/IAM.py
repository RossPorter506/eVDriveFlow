from hashlib import sha256
import os

# Placeholder code for performing software/firmware measurement 

# Get hash of files in current working directory. Because of how the project is run, this is 
# the location of the evse_gui.py file, which is ../secc and ../malicious_secc, respectively
def hash_secc_software() -> bytes:
    return _hash_dir_recursive(os.getcwd())


def _hash_dir_recursive(dir: str) -> bytes:
    hashes = bytearray()
    for (path, dirs, files) in os.walk(dir, followlinks=True):
        for file in sorted(files):
            hashes += _hash_file(os.path.join(path, file))
        for dir in sorted(dirs):
            hashes += _hash_dir_recursive(os.path.join(path, dir))
        break # dir case above does the subfolders for us
    return sha256(hashes).digest()


def _hash_file(filepath: str) -> bytes:
    with open(filepath, "rb") as f:
        hsh = sha256(f.read()).digest()
    return hsh


# Generate 'reference' hash for EVCC to use.
if __name__ == "__main__":
    # Make sure we measure the code in the ../secc folder.
    os.chdir(os.path.join( os.path.dirname(__file__), os.path.pardir, "secc"))

    hsh = hash_secc_software()

    os.chdir(os.path.join(os.path.pardir, "IAM"))

    with open("secc.sha256", "wb") as f:
        f.write(hsh)
