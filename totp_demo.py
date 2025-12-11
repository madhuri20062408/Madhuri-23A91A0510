import base64
import pyotp

def generate_totp_code(hex_seed: str) -> str:
    seed_bytes = bytes.fromhex(hex_seed)
    seed_base32 = base64.b32encode(seed_bytes).decode('utf-8')
    totp = pyotp.TOTP(seed_base32, digits=6, interval=30)
    return totp.now()

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    seed_bytes = bytes.fromhex(hex_seed)
    seed_base32 = base64.b32encode(seed_bytes).decode('utf-8')
    totp = pyotp.TOTP(seed_base32, digits=6, interval=30)
    return totp.verify(code, valid_window=valid_window)

if __name__ == "__main__":
    hex_seed = "10a23b53b35a9e423b9b656fc2ffc321a80d1fae573166a36b06cd7109e6f0a7"
    
    code = generate_totp_code(hex_seed)
    print("Generated TOTP:", code)
    
    is_valid = verify_totp_code(hex_seed, code)
    print("Verification result:", is_valid)
