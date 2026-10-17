"""Generate failed login attempts against the local demo backend."""

import argparse

import requests


def main():
    parser = argparse.ArgumentParser(description="Test SessionSentinel rate limiting")
    parser.add_argument("email")
    parser.add_argument("attempts", type=int, nargs="?", default=8)
    parser.add_argument("url", nargs="?", default="http://localhost:8000/login")
    args = parser.parse_args()

    for number in range(1, args.attempts + 1):
        response = requests.post(
            args.url,
            json={
                "email": args.email,
                "password": f"wrong-password-{number}",
                "device_id": "attacker-device",
            },
            timeout=10,
        )
        print(f"{number}: {response.status_code} {response.text}")


if __name__ == "__main__":
    main()
