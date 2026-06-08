from curl_cffi import requests
import curl_cffi


URL = "https://tls.browserleaks.com/json"
PROFILES = ["brave136_mac", "brave145_mac", "tor1508"]


def main() -> None:
    print("curl_cffi version:", curl_cffi.__version__)

    for profile in PROFILES:
        response = requests.get(URL, impersonate=profile, timeout=20)
        response.raise_for_status()
        data = response.json()
        print(f"[{profile}] JA4: {data.get('ja4')}")


if __name__ == "__main__":
    main()
