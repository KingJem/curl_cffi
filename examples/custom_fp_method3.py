"""
方案三：使用 ja3= / akamai= / extra_fp= 完全自定义 TLS + HTTP/2 指纹

原理：
  curl_cffi 允许直接传入 JA3 字符串（指定 TLS 参数）和 Akamai 字符串
  （指定 HTTP/2 参数），以及 extra_fp 字典（补充 JA3/Akamai 未覆盖的字段）。
  无需重新编译，适用于任意指纹，包括 Brave 和 Tor Browser。

JA3 格式（逗号分隔 5 段）：
  TLS版本, 密码套件(连字符), 扩展ID(连字符), 支持的曲线(连字符), EC点格式

Akamai / HTTP2 格式（管道分隔 4 段）：
  SETTINGS(分号), WINDOW_UPDATE, PRIORITY, 伪头顺序(逗号)

依赖：pip install curl-cffi
"""

import curl_cffi.requests as requests

URL = "https://tls.browserleaks.com/json"


# ─── Brave 136 / Chrome 136 TLS 参数 ────────────────────────────────────────
#
# 密码套件 ID（十进制）：
#   4865 = TLS_AES_128_GCM_SHA256
#   4866 = TLS_AES_256_GCM_SHA384
#   4867 = TLS_CHACHA20_POLY1305_SHA256
#   49195 = ECDHE-ECDSA-AES128-GCM-SHA256  ...
#
# 曲线 ID：
#   4588 = X25519MLKEM768（PQ混合）
#   29   = X25519
#   23   = P-256
#   24   = P-384
#
# 扩展 ID（含 GREASE 占位符，JA3 中用 0 表示 GREASE）：
#   0=SNI, 23=extended_master_secret, 65281=renegotiation_info,
#   10=supported_groups, 11=ec_point_formats, 35=session_ticket,
#   16=ALPN, 5=status_request, 13=sig_algs, 18=SCT,
#   51=key_share, 45=psk_key_exchange_modes, 43=supported_versions,
#   27=compress_cert, 17613=ALPS(new), 65037=ECH

BRAVE136_JA3 = ",".join([
    "771",   # TLS 1.2 作为最低版本（实际协商 TLS 1.3）
    "4865-4866-4867-49195-49196-52393-49199-49200-52392"
    "-49171-49172-156-157-47-53",
    "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613-65037",
    "4588-29-23-24",
    "0",
])

BRAVE136_AKAMAI = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

BRAVE136_EXTRA_FP = {
    "tls_grease": True,
    "tls_permute_extensions": True,   # Chrome 110+ 特征：扩展随机排列
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
    ],
    "http2_stream_weight": 256,
    "http2_stream_exclusive": 1,
}

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


# ─── Tor Browser 15.0.8 (Firefox 140) 指纹 ──────────────────────────────────
#
# 数据来源：meek-lite 网桥流量 Wireshark 抓包
#   目标: 192.42.116.12:443，SNI: www.mp35xnmwjb37dd4oz.com
#
# 密码套件（Firefox 格式）：
#   4865 = TLS_AES_128_GCM_SHA256
#   4867 = TLS_CHACHA20_POLY1305_SHA256
#   4866 = TLS_AES_256_GCM_SHA384
#   49195~49200 = ECDHE-ECDSA/RSA-AES*-GCM
#   52393/52392 = ECDHE-*-CHACHA20-POLY1305
#   49161~49172 = ECDHE/RSA-AES-CBC
#   156/157/47/53 = RSA-AES-*
#
# 曲线 ID：
#   4588 = X25519MLKEM768
#   29   = X25519
#   23   = P-256
#   24   = P-384
#   25   = P-521
#   256/257 = ffdhe2048/ffdhe3072
#
# 扩展顺序（固定，Firefox 不随机排列）：
#   0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037

TOR1508_JA3 = ",".join([
    "771",
    "4865-4867-4866-49195-49199-52393-52392-49196-49200"
    "-49162-49161-49171-49172-156-157-47-53",
    "0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037",
    "4588-29-23-24-25-256-257",
    "0",
])

# HTTP/2: Firefox 伪头顺序 mpas（:method :path :authority :scheme）
# SETTINGS: HEADER_TABLE_SIZE=65536; ENABLE_PUSH=0;
#           INITIAL_WINDOW_SIZE=131072; MAX_FRAME_SIZE=16384
# WINDOW_UPDATE: 12517377
TOR1508_AKAMAI = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"

TOR1508_EXTRA_FP = {
    "tls_grease": False,
    "tls_permute_extensions": False,      # Firefox 不随机排列扩展
    "tls_cert_compression": "zlib",       # Firefox 首选 zlib（其次 brotli、zstd）
    "tls_record_size_limit": 4001,        # Firefox extension 28
    "tls_delegated_credential": (         # Firefox extension 34
        "ecdsa_secp256r1_sha256:"
        "ecdsa_secp384r1_sha384:"
        "ecdsa_secp521r1_sha512:"
        "ecdsa_sha1"
    ),
    "tls_signature_algorithms": [
        "ecdsa_secp256r1_sha256",
        "ecdsa_secp384r1_sha384",
        "ecdsa_secp521r1_sha512",
        "rsa_pss_rsae_sha256",
        "rsa_pss_rsae_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha256",
        "rsa_pkcs1_sha384",
        "rsa_pkcs1_sha512",
    ],
    "http2_stream_weight": 42,
    "http2_stream_exclusive": 0,
    "http2_no_priority": True,   # Firefox 不发送 PRIORITY 帧
}

TOR1508_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; rv:140.0) "
        "Gecko/20100101 Firefox/140.0"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Priority": "u=0, i",
}


# ─── 工具函数 ────────────────────────────────────────────────────────────────

def fetch(name: str, ja3: str, akamai: str, extra_fp: dict, headers: dict) -> dict:
    with requests.Session() as session:
        resp = session.get(
            URL,
            ja3=ja3,
            akamai=akamai,
            extra_fp=extra_fp,
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()


def print_fingerprint(profile_name: str, data: dict):
    print(f"\n{'='*60}")
    print(f"  Profile  : {profile_name}")
    print(f"  JA3      : {data.get('ja3_hash', 'N/A')}")
    print(f"  JA4      : {data.get('ja4', 'N/A')}")
    print(f"  UA       : {data.get('user_agent', 'N/A')}")
    print(f"{'='*60}")


# ─── 主程序 ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    profiles = [
        (
            "brave136_mac (Method 3)",
            BRAVE136_JA3,
            BRAVE136_AKAMAI,
            BRAVE136_EXTRA_FP,
            BRAVE136_MAC_HEADERS,
        ),
        (
            "tor1508 / Firefox 140 (Method 3)",
            TOR1508_JA3,
            TOR1508_AKAMAI,
            TOR1508_EXTRA_FP,
            TOR1508_HEADERS,
        ),
    ]

    for name, ja3, akamai, extra_fp, headers in profiles:
        try:
            data = fetch(name, ja3, akamai, extra_fp, headers)
            print_fingerprint(name, data)
        except Exception as e:
            print(f"[{name}] 请求失败: {e}")
