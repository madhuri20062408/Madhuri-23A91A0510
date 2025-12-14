import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# 1. Read commit hash from file
with open("commit.txt", "r") as f:
    commit_hash = f.read().strip().encode("utf-8")

# 2. Load student private key
with open("student_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# 3. Sign the commit hash using RSA-PSS + SHA256
signature = private_key.sign(
    commit_hash,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256(),
)

# 4. Base64 encode for the form
signature_b64 = base64.b64encode(signature).decode("utf-8")

print("Encrypted Commit Signature (base64):")
print(signature_b64)
