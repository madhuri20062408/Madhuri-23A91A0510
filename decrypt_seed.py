import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def decrypt_seed(encrypted_seed_b64, private_key_file="student_private.pem", output_file="seed.txt"):
    # Check if private key exists
    if not os.path.exists(private_key_file):
        print(f"Error: Private key file '{private_key_file}' not found.")
        return None

    # Load private key
    try:
        with open(private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

    # Decode base64
    try:
        encrypted_bytes = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        print(f"Error decoding base64: {e}")
        return None

    # Decrypt
    try:
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Decrypted bytes length:", len(decrypted))  # DEBUG
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

    # Convert to hex string and validate
    try:
        seed_hex = decrypted.hex()  # <-- convert bytes to 64-char hex
        if len(seed_hex) != 64:
            raise ValueError("Invalid seed length")
    except Exception as e:
        print(f"Error validating seed: {e}")
        return None

    # Write to output file
    try:
        with open(output_file, "w") as f:
            f.write(seed_hex)
        print(f"Decrypted seed saved to '{output_file}'")
    except Exception as e:
        print(f"Error writing seed to file: {e}")
        return None

    return seed_hex


if __name__ == "__main__":
    encrypted_file = "encrypted_seed.txt"
    
    if not os.path.exists(encrypted_file):
        print(f"Error: Encrypted file '{encrypted_file}' not found.")
    else:
        with open(encrypted_file, "r") as f:
            encrypted_seed_b64 = f.read().strip()

        seed = decrypt_seed(encrypted_seed_b64)
        if seed:
            print("Decrypted seed:", seed)
