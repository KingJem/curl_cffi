# curl_cffi 指纹参数完全手册

> 源码版本：`curl_cffi 0.15.3`
> 涉及文件：`curl_cffi/requests/impersonate.py`、`curl_cffi/requests/utils.py`、`curl_cffi/const.py`

---

## 目录

1. [参数体系概览](#1-参数体系概览)
2. [ja3= 参数](#2-ja3-参数)
3. [akamai= 参数](#3-akamai-参数)
4. [extra_fp= 参数（ExtraFingerprints）](#4-extra_fp-参数extrafingerprints)
5. [参数执行顺序与优先级](#5-参数执行顺序与优先级)
6. [TLS 扩展 ID 速查表](#6-tls-扩展-id-速查表)
7. [完整使用示例](#7-完整使用示例)

---

## 1. 参数体系概览

curl_cffi 的指纹参数分为三层，共同控制 TLS + HTTP/2 握手行为：

```
┌──────────────────────────────────────────────────────┐
│  impersonate=                                        │
│  使用内置浏览器 Profile（含完整 TLS + HTTP/2 配置）   │
│  可被 ja3 / akamai / extra_fp 覆盖                   │
├──────────────────────────────────────────────────────┤
│  ja3=          TLS ClientHello 指纹（5段字符串）      │
│  akamai=       HTTP/2 握手指纹（4段字符串）           │
│  extra_fp=     细粒度补充控制（dataclass 或 dict）    │
└──────────────────────────────────────────────────────┘
```

**Session 级别参数**（作为会话默认值）与 **Request 级别参数**（覆盖 Session 默认值）均受支持：

```python
# Session 级：整个 Session 使用同一指纹
session = requests.Session(impersonate="chrome136", ja3="...", akamai="...", extra_fp={...})

# Request 级：单次请求覆盖
r = session.get(url, ja3="...", akamai="...", extra_fp={...})
```

---

## 2. ja3= 参数

### 格式

```
TLS版本,密码套件,扩展ID,支持的曲线,EC点格式
```

五段以逗号分隔，各段内以连字符分隔各 ID（均为十进制整数）：

```python
ja3 = "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0"
```

---

### 各段详解

#### 段 1：TLS 版本

| 值 | TLS 版本 |
|---|---|
| `769` | TLS 1.0 |
| `770` | TLS 1.1 |
| `771` | TLS 1.2（最常用）|
| `772` | TLS 1.3 |

> ⚠️ 当前 curl_cffi 只支持 `771`（TLS 1.2）作为最低版本，实际协商版本仍可达 TLS 1.3。

#### 段 2：密码套件（连字符分隔的十进制 ID）

常用密码套件：

| 十进制 | 十六进制 | 名称 |
|---|---|---|
| 4865 | 0x1301 | TLS_AES_128_GCM_SHA256 |
| 4866 | 0x1302 | TLS_AES_256_GCM_SHA384 |
| 4867 | 0x1303 | TLS_CHACHA20_POLY1305_SHA256 |
| 49195 | 0xC02B | ECDHE-ECDSA-AES128-GCM-SHA256 |
| 49196 | 0xC02C | ECDHE-ECDSA-AES256-GCM-SHA384 |
| 52393 | 0xCCA9 | ECDHE-ECDSA-CHACHA20-POLY1305 |
| 49199 | 0xC02F | ECDHE-RSA-AES128-GCM-SHA256 |
| 49200 | 0xC030 | ECDHE-RSA-AES256-GCM-SHA384 |
| 52392 | 0xCCA8 | ECDHE-RSA-CHACHA20-POLY1305 |
| 49171 | 0xC013 | ECDHE-RSA-AES128-CBC-SHA |
| 49172 | 0xC014 | ECDHE-RSA-AES256-CBC-SHA |
| 156 | 0x009C | AES128-GCM-SHA256 |
| 157 | 0x009D | AES256-GCM-SHA384 |
| 47 | 0x002F | AES128-SHA |
| 53 | 0x0035 | AES256-SHA |

**映射到 CurlOpt：** `CurlOpt.SSL_CIPHER_LIST`（以冒号连接名称字符串）

#### 段 3：扩展 ID（连字符分隔）

控制哪些 TLS 扩展出现在 ClientHello 中，顺序会被保留（除非开启了 `tls_permute_extensions`）。

| ID | 扩展名 | 说明 |
|---|---|---|
| 0 | server_name | SNI（必须包含）|
| 5 | status_request | OCSP stapling |
| 10 | supported_groups | 椭圆曲线列表 |
| 11 | ec_point_formats | EC 点格式 |
| 13 | signature_algorithms | 签名算法（ext 13）|
| 16 | ALPN | 协议协商（h2/http/1.1）|
| 17513 | application_settings | ALPS（旧 codepoint，BoringSSL 私有）|
| 17613 | application_settings | ALPS（新 codepoint，BoringSSL 私有）|
| 18 | signed_certificate_timestamp | SCT |
| 21 | padding | 填充（curl 自动处理，会被忽略）|
| 23 | extended_master_secret | 主密钥扩展 |
| 27 | compress_certificate | 证书压缩（zlib/brotli）|
| 28 | record_size_limit | 记录大小限制（Firefox 特有）|
| 34 | delegated_credential | 委托凭证（Firefox 特有）|
| 35 | session_ticket | Session Ticket |
| 43 | supported_versions | 支持的 TLS 版本列表 |
| 45 | psk_key_exchange_modes | PSK 交换模式 |
| 51 | key_share | 密钥共享（TLS 1.3）|
| 57 | quic_transport_parameters | QUIC 传输参数（HTTP/3）|
| 65037 | encrypted_client_hello | ECH |
| 65281 | renegotiation_info | 重协商信息 |

**映射到 CurlOpt：** `CurlOpt.TLS_EXTENSION_ORDER`（按 ja3 字符串中的顺序）

> ⚠️ 若同时设置了 `extra_fp.tls_permute_extensions=True`，扩展顺序将被随机化，ja3 中的顺序不会被应用。

#### 段 4：支持的曲线（EC 曲线）

| ID | 曲线名 | 说明 |
|---|---|---|
| 23 | P-256 | secp256r1 |
| 24 | P-384 | secp384r1 |
| 25 | P-521 | secp521r1 |
| 29 | X25519 | 最广泛支持的曲线 |
| 256 | ffdhe2048 | 有限域 DH |
| 257 | ffdhe3072 | 有限域 DH |
| 4588 | X25519MLKEM768 | 混合后量子密码（Chrome 131+）|
| 25497 | X25519Kyber768Draft00 | 混合后量子密码（草案）|

**映射到 CurlOpt：** `CurlOpt.SSL_EC_CURVES`（以冒号连接名称字符串）

#### 段 5：EC 点格式

固定填 `0`（非压缩格式），curl_cffi 只支持此值，否则抛出 `AssertionError`。

---

### ja3 注意事项

- **Chrome 的 JA3 是变化的**：因为 Chrome 启用了 `tls_permute_extensions`，每次连接扩展顺序随机，JA3 哈希每次不同。推荐用 **JA4**（排序后哈希，稳定）。
- **扩展 21（padding）** 会被自动去掉，并产生警告。
- **GREASE 值**（0x0A0A 等）在 JA3 中通常表示为 `0`，不出现在 JA4 中。

---

## 3. akamai= 参数

### 格式

```
SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
```

四段以管道符 `|` 分隔，对应 HTTP/2 握手的四个关键特征。

```python
akamai = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
```

---

### 各段详解

#### 段 1：SETTINGS（HTTP/2 SETTINGS 帧）

格式：`ID:值;ID:值;...`（支持 `;` 分隔或 `,` 分隔，自动兼容）

| ID | 含义 | 常见值 |
|---|---|---|
| `1` | HEADER_TABLE_SIZE — HPACK 动态表最大大小（字节）| 65536（Chrome）、4096（默认）|
| `2` | ENABLE_PUSH — 服务端推送开关 | `0`（禁用，Chrome/Firefox）、`1`（启用）|
| `3` | MAX_CONCURRENT_STREAMS — 最大并发流数 | `100`（Firefox）、省略（Chrome）|
| `4` | INITIAL_WINDOW_SIZE — 初始流控窗口大小（字节）| `6291456`（Chrome）、`131072`（Firefox）|
| `5` | MAX_FRAME_SIZE — 最大帧载荷（字节）| `16384`（Firefox）、省略（Chrome）|
| `6` | MAX_HEADER_LIST_SIZE — 最大头部列表大小（字节）| `262144`（Chrome）|

**映射到 CurlOpt：** `CurlOpt.HTTP2_SETTINGS`

**各浏览器示例：**

```python
chrome136   = "1:65536;2:0;4:6291456;6:262144"
firefox_147 = "1:65536;2:0;4:131072;5:16384"
safari_26   = "2:0;4:4194304;3:100"
okhttp4     = "4:16777216"
```

#### 段 2：WINDOW_UPDATE（连接级流控窗口）

格式：单个十进制整数

| 值 | 含义 |
|---|---|
| `0` | 不发送 WINDOW_UPDATE 帧 |
| `15663105` | Chrome（约 15 MB）|
| `12517377` | Firefox（约 12 MB）|
| `10485760` | Safari（10 MB）|
| `16711681` | OkHttp |

**映射到 CurlOpt：** `CurlOpt.HTTP2_WINDOW_UPDATE`

> WINDOW_UPDATE 是连接层（非流层）的流控窗口增量，数值越大服务端可以推送的数据量越多。

#### 段 3：PRIORITY（HTTP/2 优先级帧）

格式：`StreamID:ExclusiveBit:DependentStreamID:Weight`，多个帧用逗号分隔；`0` 表示不发送。

| 字段 | 取值 | 说明 |
|---|---|---|
| StreamID | 整数（奇数）| 客户端发起的流 ID，通常为 `3`、`5`、`7` |
| ExclusiveBit | `0` 或 `1` | `1` = 此流成为父流的唯一依赖；`0` = 共享依赖 |
| DependentStreamID | 整数 | 依赖的父流 ID，`0` = 依赖根节点 |
| Weight | 1~256 | 相对优先权重 |

**映射到 CurlOpt：** `CurlOpt.HTTP2_STREAMS`

**示例：**

```python
# Chrome：不发送 PRIORITY 帧
priority = "0"

# Safari：一组优先帧
priority = "3:0:0:201,5:0:3:101,7:0:5:1"

# Firefox：不发送 PRIORITY 帧（配合 http2_no_priority=True）
priority = "0"
```

#### 段 4：伪头顺序（Pseudo-Header Order）

格式：4 个字母的排列，可用逗号分隔（自动去除逗号）

| 字母 | 含义 |
|---|---|
| `m` | `:method` |
| `a` | `:authority` |
| `s` | `:scheme` |
| `p` | `:path` |

**映射到 CurlOpt：** `CurlOpt.HTTP2_PSEUDO_HEADERS_ORDER`（逗号自动去除）

**各浏览器伪头顺序：**

| 浏览器 | 顺序 |
|---|---|
| Chrome | `m,a,s,p` |
| Firefox | `m,p,a,s` |
| Safari | `m,s,p,a` |
| OkHttp | `m,p,a,s` |

---

### 完整 akamai 示例

```python
# Chrome 136（macOS）
akamai_chrome136 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

# Firefox 147
akamai_firefox147 = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"

# Safari 26.0
akamai_safari260  = "2:0;4:4194304;3:100|10485760|0|m,s,p,a"

# OkHttp 4（Android 10）
akamai_okhttp4    = "4:16777216|16711681|0|m,p,a,s"
```

---

## 4. extra_fp= 参数（ExtraFingerprints）

`extra_fp` 接受 `ExtraFingerprints` dataclass 实例，或者直接传入 `dict`（`ExtraFpDict`）。

```python
from curl_cffi.requests.impersonate import ExtraFingerprints
from curl_cffi import CurlSslVersion

# dataclass 方式
fp = ExtraFingerprints(tls_grease=True, tls_permute_extensions=True)

# dict 方式（等效）
fp = {"tls_grease": True, "tls_permute_extensions": True}
```

---

### 字段完整说明

#### 4.1 tls_min_version

| 项目 | 内容 |
|---|---|
| 类型 | `int` |
| 默认值 | `CurlSslVersion.TLSv1_2`（值 = 6）|
| 映射 CurlOpt | `CurlOpt.SSLVERSION` |
| 作用 | 设置 TLS 最低版本，实际发出的 ClientHello 支持版本从此值到库默认最高版本 |

```python
from curl_cffi import CurlSslVersion

extra_fp = {"tls_min_version": CurlSslVersion.TLSv1_2}  # 默认
extra_fp = {"tls_min_version": CurlSslVersion.TLSv1_3}  # 强制只用 TLS 1.3
```

| 常量 | 值 | 说明 |
|---|---|---|
| `CurlSslVersion.TLSv1_0` | 4 | TLS 1.0 |
| `CurlSslVersion.TLSv1_1` | 5 | TLS 1.1 |
| `CurlSslVersion.TLSv1_2` | 6 | TLS 1.2（推荐）|
| `CurlSslVersion.TLSv1_3` | 7 | TLS 1.3 |

---

#### 4.2 tls_grease

| 项目 | 内容 |
|---|---|
| 类型 | `bool` |
| 默认值 | `False` |
| 映射 CurlOpt | `CurlOpt.TLS_GREASE` |
| 作用 | 在 ClientHello 中插入随机 GREASE 值（随机密码套件、扩展、曲线 ID），是 Chrome 的典型特征 |

```python
extra_fp = {"tls_grease": True}   # Chrome 行为
extra_fp = {"tls_grease": False}  # Firefox / Safari / 默认
```

> **GREASE**（RFC 8701）：在 TLS 握手中插入服务端应忽略的随机值，防止服务端按指纹拒绝连接。Chrome 默认开启。

---

#### 4.3 tls_permute_extensions

| 项目 | 内容 |
|---|---|
| 类型 | `bool` |
| 默认值 | `False` |
| 映射 CurlOpt | `CurlOpt.SSL_PERMUTE_EXTENSIONS` |
| 作用 | 每次连接随机打乱 TLS 扩展顺序。Chrome 110+ 行为，导致 JA3 每次不同，但 JA4 稳定 |

```python
extra_fp = {"tls_permute_extensions": True}   # Chrome 110+
extra_fp = {"tls_permute_extensions": False}  # Firefox / Safari（固定顺序）
```

> ⚠️ 启用后，`ja3=` 中设置的扩展顺序不会被应用（`set_ja3_options` 在 permute=True 时跳过 `TLS_EXTENSION_ORDER` 的 setopt）。

---

#### 4.4 tls_cert_compression

| 项目 | 内容 |
|---|---|
| 类型 | `Literal["zlib", "brotli"]` |
| 默认值 | `"brotli"` |
| 映射 CurlOpt | `CurlOpt.SSL_CERT_COMPRESSION` |
| TLS 扩展 | 27 (compress_certificate) |
| 作用 | 声明客户端支持的证书压缩算法，减少握手数据量 |

```python
extra_fp = {"tls_cert_compression": "brotli"}  # Chrome（默认）
extra_fp = {"tls_cert_compression": "zlib"}    # Firefox
```

> 如果在 `ja3=` 中包含扩展 `27`，建议显式设置此字段；否则 curl_cffi 会产生警告并默认使用 `"brotli"`。

---

#### 4.5 tls_signature_algorithms

| 项目 | 内容 |
|---|---|
| 类型 | `Optional[list[str]]` |
| 默认值 | `None`（使用 curl 内置默认）|
| 映射 CurlOpt | `CurlOpt.SSL_SIG_HASH_ALGS`（逗号拼接）|
| TLS 扩展 | 13 (signature_algorithms) |
| 作用 | 覆盖 ClientHello 中的签名算法列表及其顺序，是 JA3/JA4 指纹的重要组成部分 |

```python
# Chrome 136 签名算法
extra_fp = {
    "tls_signature_algorithms": [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
    ]
}

# Firefox / OkHttp（末尾额外含 rsa_pkcs1_sha1）
extra_fp = {
    "tls_signature_algorithms": [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
        "rsa_pkcs1_sha1",  # Firefox / OkHttp 额外包含
    ]
}
```

**完整可用算法名：**

| 算法名 | 说明 |
|---|---|
| `ecdsa_secp256r1_sha256` | ECDSA P-256 + SHA-256 |
| `ecdsa_secp384r1_sha384` | ECDSA P-384 + SHA-384 |
| `ecdsa_secp521r1_sha512` | ECDSA P-521 + SHA-512（Firefox 特有）|
| `rsa_pss_rsae_sha256` | RSA-PSS + SHA-256 |
| `rsa_pss_rsae_sha384` | RSA-PSS + SHA-384 |
| `rsa_pss_rsae_sha512` | RSA-PSS + SHA-512 |
| `rsa_pkcs1_sha256` | PKCS#1 v1.5 + SHA-256 |
| `rsa_pkcs1_sha384` | PKCS#1 v1.5 + SHA-384 |
| `rsa_pkcs1_sha512` | PKCS#1 v1.5 + SHA-512 |
| `rsa_pkcs1_sha1` | PKCS#1 v1.5 + SHA-1（旧版，Firefox/OkHttp）|
| `ecdsa_sha1` | ECDSA + SHA-1（旧版，Firefox 委托凭证）|

---

#### 4.6 tls_delegated_credential

| 项目 | 内容 |
|---|---|
| 类型 | `str` |
| 默认值 | `""` (不启用) |
| 映射 CurlOpt | `CurlOpt.TLS_DELEGATED_CREDENTIALS` |
| TLS 扩展 | 34 (delegated_credential) |
| 作用 | Firefox 特有扩展，允许服务端使用委托的短期证书，需与 ja3 中包含扩展 `34` 配合使用 |

```python
# Firefox 147 的委托凭证配置
extra_fp = {
    "tls_delegated_credential": (
        "ecdsa_secp256r1_sha256:"
        "ecdsa_secp384r1_sha384:"
        "ecdsa_secp521r1_sha512:"
        "ecdsa_sha1"
    )
}
```

> 格式为冒号分隔的算法名列表。只有 Firefox 会发送此扩展，Chrome/Safari 不支持。

---

#### 4.7 tls_record_size_limit

| 项目 | 内容 |
|---|---|
| 类型 | `int` |
| 默认值 | `0`（不发送）|
| 映射 CurlOpt | `CurlOpt.TLS_RECORD_SIZE_LIMIT` |
| TLS 扩展 | 28 (record_size_limit) |
| 作用 | 向服务端声明客户端接受的最大 TLS 记录大小。Firefox 使用此扩展，值为 4001 字节 |

```python
extra_fp = {"tls_record_size_limit": 4001}  # Firefox 特征值
```

> 需要在 `ja3=` 的扩展 ID 段中包含 `28`，否则服务端不会看到该字段。

---

#### 4.8 http2_stream_weight

| 项目 | 内容 |
|---|---|
| 类型 | `int` |
| 默认值 | `256` |
| 映射 CurlOpt | `CurlOpt.STREAM_WEIGHT` |
| 作用 | 设置 HTTP/2 PRIORITY 帧中的流权重（1~256）。Chrome 使用 256，Firefox 不发送 PRIORITY 帧 |

```python
extra_fp = {"http2_stream_weight": 256}  # Chrome（默认）
extra_fp = {"http2_stream_weight": 42}   # Firefox（配合 http2_no_priority=True）
```

> ⚠️ 若设置了 `akamai=` 参数，`akamai` 的 PRIORITY 段会覆盖此值。

---

#### 4.9 http2_stream_exclusive

| 项目 | 内容 |
|---|---|
| 类型 | `int` |
| 默认值 | `1` |
| 映射 CurlOpt | `CurlOpt.STREAM_EXCLUSIVE` |
| 作用 | 设置 HTTP/2 PRIORITY 帧的 Exclusive 位。`1` = 独占（Chrome），`0` = 共享依赖（部分 Safari）|

```python
extra_fp = {"http2_stream_exclusive": 1}  # Chrome（默认）
extra_fp = {"http2_stream_exclusive": 0}  # Safari / OkHttp
```

---

#### 4.10 http2_no_priority

| 项目 | 内容 |
|---|---|
| 类型 | `bool` |
| 默认值 | `False` |
| 映射 CurlOpt | `CurlOpt.HTTP2_NO_PRIORITY` |
| 作用 | 完全禁用 HTTP/2 优先级机制，不发送 PRIORITY 帧。Firefox 的典型行为 |

```python
extra_fp = {"http2_no_priority": True}   # Firefox
extra_fp = {"http2_no_priority": False}  # Chrome / Safari（默认）
```

> 启用后，`http2_stream_weight` 和 `http2_stream_exclusive` 的设置被忽略。

---

#### 4.11 split_cookies

| 项目 | 内容 |
|---|---|
| 类型 | `Optional[bool]` |
| 默认值 | `None`（使用 Profile 的默认值）|
| 映射 CurlOpt | `CurlOpt.SPLIT_COOKIES` |
| 作用 | `True` = 每个 Cookie 单独一个 `Cookie:` 请求头；`False` = 所有 Cookie 合并在一个头里。Chrome 使用分割模式 |

```python
extra_fp = {"split_cookies": True}   # Chrome 行为
extra_fp = {"split_cookies": False}  # Firefox / 标准行为
```

---

#### 4.12 form_boundary

| 项目 | 内容 |
|---|---|
| 类型 | `Optional[bool]` |
| 默认值 | `None` |
| 映射 CurlOpt | `CurlOpt.FORM_BOUNDARY` |
| 作用 | 控制 multipart/form-data 的 boundary 格式（Chrome 使用 WebKit 格式） |

```python
extra_fp = {"form_boundary": True}   # Chrome/WebKit 格式
extra_fp = {"form_boundary": False}  # 标准格式
```

---

#### 4.13 http3_sig_hash_algs

| 项目 | 内容 |
|---|---|
| 类型 | `Optional[str]` |
| 默认值 | `None` |
| 映射 CurlOpt | `CurlOpt.HTTP3_SIG_HASH_ALGS` |
| 作用 | 设置 HTTP/3 (QUIC) TLS 握手中的签名算法列表，与 `tls_signature_algorithms` 作用相同但针对 HTTP/3 |

```python
extra_fp = {
    "http3_sig_hash_algs": (
        "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:"
        "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:"
        "rsa_pss_rsae_sha512:rsa_pkcs1_sha512"
    )
}
```

> 格式为冒号分隔字符串（与 `tls_signature_algorithms` 的列表格式不同）。

---

#### 4.14 http3_tls_extension_order

| 项目 | 内容 |
|---|---|
| 类型 | `Optional[str]` |
| 默认值 | `None` |
| 映射 CurlOpt | `CurlOpt.HTTP3_TLS_EXTENSION_ORDER` |
| 作用 | 设置 HTTP/3 (QUIC) TLS 握手中的扩展顺序，格式与 ja3 中的扩展 ID 段相同 |

```python
# Chrome 145 HTTP/3 扩展顺序
extra_fp = {
    "http3_tls_extension_order": "0-10-13-16-27-43-45-51-57-17613-65037"
}
```

---

### ExtraFingerprints 字段速查表

| 字段 | 类型 | 默认值 | CurlOpt | TLS扩展 | 说明 |
|---|---|---|---|---|---|
| `tls_min_version` | int | TLSv1_2 | SSLVERSION | — | TLS 最低版本 |
| `tls_grease` | bool | False | TLS_GREASE | — | Chrome 特征 |
| `tls_permute_extensions` | bool | False | SSL_PERMUTE_EXTENSIONS | — | Chrome 110+，随机化扩展顺序 |
| `tls_cert_compression` | str | "brotli" | SSL_CERT_COMPRESSION | 27 | 证书压缩 |
| `tls_signature_algorithms` | list | None | SSL_SIG_HASH_ALGS | 13 | 签名算法列表 |
| `tls_delegated_credential` | str | "" | TLS_DELEGATED_CREDENTIALS | 34 | Firefox 特有 |
| `tls_record_size_limit` | int | 0 | TLS_RECORD_SIZE_LIMIT | 28 | Firefox 特有，值 4001 |
| `http2_stream_weight` | int | 256 | STREAM_WEIGHT | — | HTTP/2 优先级权重 |
| `http2_stream_exclusive` | int | 1 | STREAM_EXCLUSIVE | — | HTTP/2 优先级独占位 |
| `http2_no_priority` | bool | False | HTTP2_NO_PRIORITY | — | Firefox，禁用优先级帧 |
| `split_cookies` | bool? | None | SPLIT_COOKIES | — | Chrome，单独发送每个 Cookie |
| `form_boundary` | bool? | None | FORM_BOUNDARY | — | multipart boundary 格式 |
| `http3_sig_hash_algs` | str? | None | HTTP3_SIG_HASH_ALGS | — | HTTP/3 签名算法 |
| `http3_tls_extension_order` | str? | None | HTTP3_TLS_EXTENSION_ORDER | — | HTTP/3 扩展顺序 |

---

## 5. 参数执行顺序与优先级

`set_curl_options()` 中的执行顺序（`utils.py` 约 660~710 行）：

```
1. impersonate        ← 设置完整 Browser Profile（TLS + HTTP/2 + 默认 Headers）
         ↓ 可被后续参数覆盖
2. ja3                ← 覆盖 TLS 密码套件、曲线、扩展
3. extra_fp           ← 覆盖 GREASE、permute、签名算法、HTTP/2 权重等
4. akamai             ← 覆盖 HTTP/2 SETTINGS、WINDOW_UPDATE、PRIORITY、伪头顺序
5. perk               ← 同 akamai 格式，用于 HTTP/3
```

**覆盖规则：**

- `akamai` 的 PRIORITY 段会覆盖 `extra_fp` 的 `http2_stream_weight` 和 `http2_stream_exclusive`
- `ja3` 的扩展顺序被 `extra_fp.tls_permute_extensions=True` 覆盖
- Request 级参数覆盖 Session 级参数

**警告机制：** 同时设置了 `impersonate` 和 `ja3/extra_fp/akamai` 时，会触发警告：

```
UserWarning: Using custom ja3/extra_fp will override the impersonate setting.
```

---

## 6. TLS 扩展 ID 速查表

| ID | 名称 | 浏览器 | curl_cffi 处理方式 |
|---|---|---|---|
| 0 | server_name (SNI) | 所有 | 不可切换（必须存在）|
| 5 | status_request | Chrome/Firefox | 开启 `TLS_STATUS_REQUEST` |
| 10 | supported_groups | 所有 | 默认开启 |
| 11 | ec_point_formats | 所有 | 默认开启 |
| 13 | signature_algorithms | 所有 | 默认开启，由 `tls_signature_algorithms` 控制内容 |
| 16 | ALPN | 所有 | 开关 `SSL_ENABLE_ALPN` |
| 17513 | application_settings (ALPS旧) | Chrome/Brave | 开启 `SSL_ENABLE_ALPS` |
| 17613 | application_settings (ALPS新) | Chrome 112+ | 开启 `SSL_ENABLE_ALPS` + `TLS_USE_NEW_ALPS_CODEPOINT` |
| 18 | signed_certificate_timestamp | Chrome/Firefox | 开启 `TLS_SIGNED_CERT_TIMESTAMPS` |
| 21 | padding | 所有 | 忽略（curl 自动处理）|
| 23 | extended_master_secret | 所有 | 默认开启 |
| 27 | compress_certificate | Chrome/Firefox | 开启 `SSL_CERT_COMPRESSION`（brotli/zlib）|
| 28 | record_size_limit | Firefox | 由 `tls_record_size_limit` 控制 |
| 34 | delegated_credential | Firefox | 由 `tls_delegated_credential` 控制 |
| 35 | session_ticket | Chrome/Firefox | 开关 `SSL_ENABLE_TICKET` |
| 43 | supported_versions | 所有 | 默认开启 |
| 45 | psk_key_exchange_modes | 所有 | 默认开启 |
| 51 | key_share | 所有 | 默认开启 |
| 65037 | encrypted_client_hello (ECH) | Chrome | 开启 `ECH = "grease"` |
| 65281 | renegotiation_info | Chrome/Firefox | 默认开启 |

---

## 7. 完整使用示例

### 示例一：模拟 OkHttp 4（Android 10）

```python
import curl_cffi.requests as requests

URL = "https://tls.browserleaks.com/json"

ja3 = ",".join([
    "771",
    "4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53",
    "0-23-65281-10-11-35-16-5-13-51-45-43-21",
    "29-23-24",
    "0",
])

akamai = "4:16777216|16711681|0|m,p,a,s"

extra_fp = {
    "tls_signature_algorithms": [
        "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512", "rsa_pkcs1_sha1",
    ]
}

r = requests.get(URL, ja3=ja3, akamai=akamai, extra_fp=extra_fp)
print(r.json())
```

---

### 示例二：模拟 Firefox 147

```python
ja3 = ",".join([
    "771",
    "4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53",
    "0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037",
    "4588-29-23-24-25-256-257",
    "0",
])

akamai = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"

extra_fp = {
    "tls_grease": False,
    "tls_permute_extensions": False,
    "tls_cert_compression": "zlib",          # Firefox 使用 zlib
    "tls_record_size_limit": 4001,           # Firefox 特有，扩展 28
    "tls_delegated_credential": (            # Firefox 特有，扩展 34
        "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:"
        "ecdsa_secp521r1_sha512:ecdsa_sha1"
    ),
    "tls_signature_algorithms": [
        "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384",
        "ecdsa_secp521r1_sha512", "rsa_pss_rsae_sha256",
        "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha256", "rsa_pkcs1_sha384", "rsa_pkcs1_sha512",
    ],
    "http2_no_priority": True,               # Firefox 不发 PRIORITY 帧
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:147.0) Gecko/20100101 Firefox/147.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br, zstd",
}

r = requests.get(URL, ja3=ja3, akamai=akamai, extra_fp=extra_fp, headers=headers)
```

---

### 示例三：模拟 Chrome 136（Brave 136 Mac）

```python
ja3 = ",".join([
    "771",
    "4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53",
    "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613-65037",
    "4588-29-23-24",
    "0",
])

akamai = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

extra_fp = {
    "tls_grease": True,
    "tls_permute_extensions": True,          # Chrome 110+：每次随机扩展顺序
    "tls_cert_compression": "brotli",
    "tls_signature_algorithms": [
        "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512",
    ],
    "http2_stream_weight": 256,
    "http2_stream_exclusive": 1,
    "split_cookies": True,
    "form_boundary": True,
}

headers = {
    "sec-ch-ua": '"Brave";v="136", "Chromium";v="136", "Not/A)Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,image/apng,*/*;"
        "q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
}

r = requests.get(URL, ja3=ja3, akamai=akamai, extra_fp=extra_fp, headers=headers)
print(r.json().get("ja4"))  # 期望: t13d1516h2_8daaf6152771_*
```

---

### 示例四：Session 级别统一指纹

```python
with requests.Session(
    ja3=ja3,
    akamai=akamai,
    extra_fp=extra_fp,
    headers=headers,
) as session:
    r1 = session.get("https://tls.browserleaks.com/json")
    r2 = session.get("https://api.example.com/data")
    # 所有请求复用同一指纹
```
