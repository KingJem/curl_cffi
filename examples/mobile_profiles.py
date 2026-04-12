"""
Experimental mobile profile examples.

These profiles are Python-side presets built from public fingerprint data.
They are useful for quick experiments, but they are not guaranteed to match
the exact behavior of a real Android/iOS app runtime.
"""

import curl_cffi.requests as requests


URL = "https://tls.browserleaks.com/json"

PROFILES = [
    "okhttp4_android10",
    "uc110_9",
    "uc17_9",
    "samsung27_1",
    "xiaomi15_9",
]


def main():
    for profile in PROFILES:
        resp = requests.get(URL, impersonate=profile)
        resp.raise_for_status()
        data = resp.json()
        print(profile, data.get("ja3_hash"), data.get("ja4"), data.get("user_agent"))


if __name__ == "__main__":
    main()
