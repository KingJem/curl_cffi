"""
方案一：impersonate 现有 Chrome Profile + 覆盖 Brave HTTP Headers

原理：
  Brave 的 TLS 指纹与同版本 Chrome 完全相同（共用 BoringSSL）。
  只需用 curl_cffi 内置的 chrome136 Profile 提供 TLS/HTTP2 指纹，
  再通过 headers 参数覆盖 sec-ch-ua、User-Agent 等 HTTP 层字段即可。

依赖：pip install curl-cffi
"""

import json
import curl_cffi.requests as requests

URL = "https://tls.browserleaks.com/json"

# ─── Brave 136 各平台 Headers ───────────────────────────────────────────────

BRAVE136_MAC_HEADERS = {
    "sec-ch-ua": '"Brave";v="136", "Chromium";v="136", "Not/A)Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/136.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,image/apng,*/*;"
        "q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
    "Priority": "u=0, i",
}

BRAVE136_WIN_HEADERS = {
    **BRAVE136_MAC_HEADERS,
    "sec-ch-ua-platform": '"Windows"',
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/136.0.0.0 Safari/537.36"
    ),
}

BRAVE136_ANDROID_HEADERS = {
    **BRAVE136_MAC_HEADERS,
    "sec-ch-ua": '"Brave";v="136", "Chromium";v="136", "Not/A)Brand";v="24"',
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 10; K) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/136.0.0.0 Mobile Safari/537.36"
    ),
}

# ─── Brave 145 各平台 Headers ───────────────────────────────────────────────
# chrome145 在 curl_cffi >= 0.14.0 可用；若没有则回退到 chrome136

BRAVE145_MAC_HEADERS = {
    **BRAVE136_MAC_HEADERS,
    "sec-ch-ua": '"Brave";v="145", "Chromium";v="145", "Not/A)Brand";v="24"',
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/145.0.0.0 Safari/537.36"
    ),
}

BRAVE145_WIN_HEADERS = {
    **BRAVE145_MAC_HEADERS,
    "sec-ch-ua-platform": '"Windows"',
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/145.0.0.0 Safari/537.36"
    ),
}

BRAVE145_ANDROID_HEADERS = {
    **BRAVE145_MAC_HEADERS,
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 10; K) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/145.0.0.0 Mobile Safari/537.36"
    ),
}

# ─── Profile 配置表 ──────────────────────────────────────────────────────────

BRAVE_PROFILES = {
    "brave136_mac":     ("chrome136", BRAVE136_MAC_HEADERS),
    "brave136_win":     ("chrome136", BRAVE136_WIN_HEADERS),
    "brave136_android": ("chrome136", BRAVE136_ANDROID_HEADERS),
    "brave145_mac":     ("chrome136", BRAVE145_MAC_HEADERS),  # 用 chrome136 TLS
    "brave145_win":     ("chrome136", BRAVE145_WIN_HEADERS),
    "brave145_android": ("chrome136", BRAVE145_ANDROID_HEADERS),
}


def fetch_brave(profile_name: str) -> dict:
    """用 Brave 指纹发送请求，返回 tls.browserleaks.com 的 JSON 响应。"""
    base_impersonate, headers = BRAVE_PROFILES[profile_name]

    with requests.Session(impersonate=base_impersonate) as session:
        resp = session.get(URL, headers=headers)
        resp.raise_for_status()
        return resp.json()


def print_fingerprint(profile_name: str, data: dict):
    print(f"\n{'='*60}")
    print(f"  Profile : {profile_name}")
    print(f"  JA3     : {data.get('ja3_hash', 'N/A')}")
    print(f"  JA4     : {data.get('ja4', 'N/A')}")
    print(f"  UA      : {data.get('user_agent', 'N/A')}")
    sec_ch = data.get("sec-ch-ua") or data.get("headers", {}).get("sec-ch-ua", "N/A")
    print(f"  sec-ch-ua: {sec_ch}")
    print(f"{'='*60}")


if __name__ == "__main__":
    for profile in BRAVE_PROFILES:
        try:
            data = fetch_brave(profile)
            print_fingerprint(profile, data)
        except Exception as e:
            print(f"[{profile}] 请求失败: {e}")
