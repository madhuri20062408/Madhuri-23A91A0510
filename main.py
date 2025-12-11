from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp
import os

app = FastAPI()

DATA_DIR = Path("data")
SEED_FILE = DATA_DIR / "seed.txt"

# Ensure data directory exists
DATA_DIR.mkdir(exist_ok=True)

# Request models
class DecryptSeedRequest(BaseModel):
    encrypted_seed: str

class Verify2FARequest(BaseModel):
    code: str

# -------------------------------
# POST /decrypt-seed
# -------------------------------
@app.post("/decrypt-seed")
def decrypt_seed(req: DecryptSeedRequest):
    try:
        # Load private key
        with open("student_private.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Decode Base64
        encrypted_bytes = base64.b64decode(req.encrypted_seed)

        # Decrypt using RSA/OAEP-SHA256
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Convert to 64-character hex
        seed_hex = decrypted_bytes.hex()
        if len(seed_hex) != 64:
            raise ValueError(f"Invalid seed length: {len(seed_hex)}")

        # Save to data/seed.txt
        with open(SEED_FILE, "w") as f:
            f.write(seed_hex)

        return {"status": "ok"}

    except Exception as e:
        print("Decryption error:", e)
        raise HTTPException(status_code=500, detail="Decryption failed")


# -------------------------------
# GET /generate-2fa
# -------------------------------
@app.get("/generate-2fa")
def generate_2fa():
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    with open(SEED_FILE, "r") as f:
        hex_seed = f.read().strip()

    totp = pyotp.TOTP(hex_seed)
    code = totp.now()
    valid_for = 30 - (int(totp.timecode()) % 30)

    return {"code": code, "valid_for": valid_for}


# -------------------------------
# POST /verify-2fa
# -------------------------------
@app.post("/verify-2fa")
def verify_2fa(req: Verify2FARequest):
    if not req.code:
        raise HTTPException(status_code=400, detail="Missing code")

    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    with open(SEED_FILE, "r") as f:
        hex_seed = f.read().strip()

    totp = pyotp.TOTP(hex_seed)
    valid = totp.verify(req.code, valid_window=1)

    return {"valid": valid}
