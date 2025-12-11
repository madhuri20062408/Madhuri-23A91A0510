from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Load private key
with open("student_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Load public key
with open("student_public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Compare keys
if private_key.public_key().public_numbers() == public_key.public_numbers():
    print("Keys match ✅")
else:
    print("Keys do NOT match ❌")
