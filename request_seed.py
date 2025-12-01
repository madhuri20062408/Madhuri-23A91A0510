import json
import requests

def request_seed(student_id, github_repo_url, api_url):
    # Read your public key (student_public.pem)
    with open("student_public.pem", "r") as f:
        public_key = f.read()

    # Prepare request body
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key
    }

    headers = {"Content-Type": "application/json"}

    # Send POST request
    response = requests.post(api_url, json=payload, headers=headers, timeout=30)

    # Convert to JSON
    data = response.json()

    # Check status
    if data.get("status") != "success":
        print("Error:", data)
        return

    encrypted_seed = data["encrypted_seed"]

    # Save encrypted seed (DO NOT COMMIT THIS FILE)
    with open("encrypted_seed.txt", "w") as f:
        f.write(encrypted_seed)

    print("Encrypted seed saved to encrypted_seed.txt")


# ------------------------------
# >>>>>> UPDATE THESE <<<<<<
# ------------------------------
student_id = "23A91A0510"
github_url = "https://github.com/madhuri20062408/Madhuri-23A91A0510.git"
api_url = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"

request_seed(student_id, github_url, api_url)
