from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..const import CurlOpt
from .impersonate import ExtraFingerprints


@dataclass(frozen=True)
class CustomProfileSpec:
    base_impersonate: Optional[object] = None
    ja3: Optional[str] = None
    akamai: Optional[str] = None
    extra_fp: Optional[ExtraFingerprints | dict[str, object]] = None
    headers: dict[str, str] = field(default_factory=dict)
    curl_options: dict[CurlOpt, object] = field(default_factory=dict)
    permute_extensions: bool = False


def _chrome_headers(version: int, *, platform: str = "macOS") -> dict[str, str]:
    if platform == "Windows":
        ua = (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{version}.0.0.0 Safari/537.36"
        )
        sec_ch_platform = '"Windows"'
    elif platform == "Android":
        ua = (
            f"Mozilla/5.0 (Linux; Android 10; K) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{version}.0.0.0 Mobile Safari/537.36"
        )
        sec_ch_platform = '"Android"'
    else:
        ua = (
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{version}.0.0.0 Safari/537.36"
        )
        sec_ch_platform = '"macOS"'

    return {
        "sec-ch-ua": (
            f'"Chromium";v="{version}", '
            f'"Google Chrome";v="{version}", '
            '"Not/A)Brand";v="24"'
        ),
        "sec-ch-ua-mobile": "?1" if platform == "Android" else "?0",
        "sec-ch-ua-platform": sec_ch_platform,
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": ua,
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


def _safari_mac_headers(version: str) -> dict[str, str]:
    return {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            f"Version/{version} Safari/605.1.15"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Priority": "u=0, i",
    }


def _safari_ios_headers(version: str, ios_version: str) -> dict[str, str]:
    return {
        "User-Agent": (
            f"Mozilla/5.0 (iPhone; CPU iPhone OS {ios_version} like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            f"Version/{version} Mobile/15E148 Safari/604.1"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Priority": "u=0, i",
    }


OKHTTP4_ANDROID10 = CustomProfileSpec(
    ja3="771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43,29-23-24,0",
    akamai="4:16777216|16711681|0|m,p,a,s",
    extra_fp={
        "tls_signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1",
        ]
    },
    curl_options={
        CurlOpt.SSL_CERT_COMPRESSION: "",
    },
)

CHROME_133 = CustomProfileSpec(
    base_impersonate="chrome133a",
    headers=_chrome_headers(133),
)

CHROME_141 = CustomProfileSpec(
    base_impersonate="chrome145",
    headers=_chrome_headers(141),
)

CHROME_143 = CustomProfileSpec(
    base_impersonate="chrome145",
    headers=_chrome_headers(143),
)

CHROME_144 = CustomProfileSpec(
    base_impersonate="chrome146",
    headers=_chrome_headers(144),
)

UC110_9 = CustomProfileSpec(
    ja3="771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037,29-23-24,0",
    akamai="1:65536;3:1000;4:6291456;6:262144;43706:3053153145|15663105|0|m,a,s,p",
    extra_fp={
        "tls_grease": True,
        "tls_permute_extensions": True,
        "tls_cert_compression": "brotli",
    },
    headers={
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/130.0.0.0 Safari/537.36 UCPC/1.1.0.9"
        )
    },
    curl_options={
        CurlOpt.TLS_KEY_SHARES_LIMIT: 2,
    },
    permute_extensions=True,
)

SAFARI_18 = CustomProfileSpec(
    base_impersonate="safari180",
    headers=_safari_mac_headers("18.0"),
)

SAFARI_18_IOS = CustomProfileSpec(
    base_impersonate="safari180_ios",
    headers=_safari_ios_headers("18.0", "18_0"),
)

SAFARI_17_IOS = CustomProfileSpec(
    base_impersonate="safari172_ios",
    headers=_safari_ios_headers("17.0", "17_0"),
)

UC17_9 = CustomProfileSpec(
    ja3="771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037-21,29-23-24,0",
    akamai="1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
    extra_fp={
        "tls_grease": True,
        "tls_permute_extensions": True,
        "tls_cert_compression": "brotli",
        "tls_signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1",
        ],
    },
    headers={
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_2 like Mac OS X; zh-CN) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/20H115 "
            "UCBrowser/17.7.8.2650 Mobile  AliApp(TUnionSDK/0.1.20.4)"
        )
    },
    permute_extensions=True,
)

SAMSUNG_27_1 = CustomProfileSpec(
    ja3="771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037,29-23-24,0",
    akamai="1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    extra_fp={
        "tls_grease": True,
        "tls_permute_extensions": True,
        "tls_cert_compression": "brotli",
        "tls_signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1",
        ],
    },
    headers={
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 10; K) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "SamsungBrowser/27.1 Chrome/125.0.0.0 Mobile Safari/537.36"
        )
    },
    permute_extensions=True,
)

XIAOMI_15_9 = CustomProfileSpec(
    ja3="771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-65037-21,29-23-24,0",
    akamai="1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
    extra_fp={
        "tls_grease": True,
        "tls_permute_extensions": True,
        "tls_cert_compression": "brotli",
        "tls_signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1",
        ],
    },
    headers={
        "User-Agent": (
            "Mozilla/5.0 (Linux; U; Android 11; zh-cn; M2006C3LC "
            "Build/RP1A.200720.011) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Version/4.0 Chrome/89.0.4389.116 Mobile Safari/537.36 "
            "XiaoMi/MiuiBrowser/15.9.16 swan-mibrowser"
        )
    },
    permute_extensions=True,
)


CUSTOM_PROFILES: dict[str, CustomProfileSpec] = {
    "okhttp4_android10": OKHTTP4_ANDROID10,
    "chrome133": CHROME_133,
    "chrome141": CHROME_141,
    "chrome143": CHROME_143,
    "chrome144": CHROME_144,
    "uc110_9": UC110_9,
    "uc17_9": UC17_9,
    "safari18": SAFARI_18,
    "safari18_ios": SAFARI_18_IOS,
    "safari17_ios": SAFARI_17_IOS,
    "samsung27_1": SAMSUNG_27_1,
    "xiaomi15_9": XIAOMI_15_9,
}


def get_custom_profile(profile_name: object) -> CustomProfileSpec | None:
    if hasattr(profile_name, "value"):
        profile_name = profile_name.value  # type: ignore[attr-defined]
    if profile_name is None:
        return None
    return CUSTOM_PROFILES.get(str(profile_name))
