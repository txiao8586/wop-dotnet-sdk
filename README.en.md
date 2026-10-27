# wop-dotnet-sdk

[![NuGet](https://img.shields.io/nuget/v/Wop.Sdk)](https://www.nuget.org/packages/Wop.Sdk/) [![Release](https://img.shields.io/github/v/release/wop-platform/wop-dotnet-sdk)](https://github.com/wop-platform/wop-dotnet-sdk/releases)
[![CI](https://github.com/wop-platform/wop-dotnet-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/wop-platform/wop-dotnet-sdk/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/github/license/wop-platform/wop-dotnet-sdk)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-net8.0%20%7C%20netstandard2.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/) [![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/wop-platform/wop-dotnet-sdk/actions/workflows/ci.yml) [![Gherkin](https://img.shields.io/badge/bdd-18%20scenarios-orange)](tests/Wop.Sdk.Tests/Features/MerchantJourney.feature) ![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/wop-platform/wop-dotnet-sdk?utm_source=oss&utm_medium=github&utm_campaign=wop-platform%2Fwop-dotnet-sdk&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)



Official merchant-side .NET SDK for the WOP gateway: encapsulates the protocol core
(suite parsing, canonicalRequest, structured signing, content-digest, L2 digital envelope,
signature verification & decryption) plus an HttpClient adapter, so merchants integrate
without touching wire-level byte formats.

- Targets: `net8.0` + `netstandard2.0` (multi-target)
- Crypto dependency (the single blessed path, E5): [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography) (successor of Portable.BouncyCastle)
- Suites (F1): `WOP-RSA3072-SHA256` / `WOP-RSA4096-SHA256` / `WOP-SM2-SM3` (both international and GM suites fully supported)
- Protocol source of truth: `wop-specs/crypto/crypto-strategy-spec.md` (v0.3-reviewed) and `wop-sdk-spec.md` (v1.0-ratified)

## Quick Start

```bash
dotnet add package Wop.Sdk   # 0.1.0 (or reference src/Wop.Sdk from source)
```

```csharp
using Wop.Sdk;

var client = WopClient.Builder()
    .AppKey("your-app-key")
    .Suite("WOP-RSA2048-SHA256")            // or WOP-SM2-SM3
    .MerchantPrivateKey(merchantPrivateKey)  // PEM or single-line Base64 (D12)
    .PlatformPublicKey(platformPublicKey)
    .Build();

// 1) Build the request draft (pure computation, zero network IO; idempotent
//    apart from CSPRNG values)
RequestDraft draft = client.BuildRequest(
    "POST", "/api/v1/pay",
    Encoding.UTF8.GetBytes("{\"orderNo\":\"20260829001\",\"amount\":100}"),
    SecurityLevel.L0);                       // L0 plaintext / L2 full envelope

// 2) Consume draft.Headers / draft.WireBody with your own HTTP stack,
//    or use the SDK adapter (DelegatingHandler pluggable):
var transport = new HttpClientTransport(
    new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) },
    "https://wop-gateway.example.com");
var (result, response) = client.Execute(transport, "POST", "/api/v1/pay", body, SecurityLevel.L0);
if (result.Ok)
{
    var plaintext = Encoding.UTF8.GetString(result.Plaintext!);
}
```

## ISV Sub-Merchant Identity (ISV D-13)

When calling business APIs on behalf of a sub-merchant, pass `subMchId` per request
(value = the sub-merchant's `plf_co_id`):

```csharp
var draft = client.BuildRequest(
    "POST", "/api/v1/orders", body, SecurityLevel.L0,
    requestId: null, subMchId: "PLF-SUB-001");
// or one-shot:
var r = client.Execute(
    "POST", "/api/v1/orders", body, SecurityLevel.L0,
    requestId: null, subMchId: "PLF-SUB-001");
```

The SDK writes `x-wop-sub-mch-id` before signing and includes it in the `x-wop-sign`
signedHeaders. Leading/trailing whitespace is trimmed; the value must be printable ASCII
(0x20–0x7E), contain no internal whitespace, and be at most 128 characters — violations
throw `WopException` (`WopErrorCode.Config`). Omitting it (or passing blank) keeps the
app's own identity: the header is absent and the header set/signature are byte-identical
to earlier versions (AC-20). The header takes effect only when the gateway sub-merchant
gray gate is open for the app and the app is an ISV app (`app_type=20`).

## Key Preparation (D12 contract)

Keys are passed as strings (PEM or single-line Base64) and parsed inside the SDK;
parse failures return explicit configuration errors (for integration self-checks).

| Suite | Merchant private key | Platform public key |
|-------|----------------------|---------------------|
| `WOP-RSA3072-SHA256` | PKCS#8 DER (Base64/PEM), 3072-bit | X.509 SubjectPublicKeyInfo DER (Base64/PEM) |
| `WOP-RSA4096-SHA256` | PKCS#8 DER, 4096-bit | SPKI DER |
| `WOP-SM2-SM3` | d = 32-byte big-endian scalar (Base64, within [1, n-1]) | Uncompressed point `04‖X‖Y`, 65 bytes (Base64, on-curve validated upfront) |

Notes:
- RSA key size is strictly checked against the suite declaration (3072/4096 mismatch is rejected).
- SM2 public points not on the sm2p256v1 curve are rejected immediately (I5 curve guard).
- .NET's `BitConverter.ToString` produces uppercase hyphenated output by default — this SDK
  emits **lowercase** hex everywhere (D10).

## L0 + L2 Examples

```csharp
// L0 plaintext: signature + digest integrity (digest is the only integrity line for L0, D2)
var l0 = client.BuildRequest("GET", "/api/v1/orders?status=PAID", null, SecurityLevel.L0);
// GET / empty body: x-wop-content-digest header is absent (no "digest of empty string" state)

// L2 full digital envelope: CSPRNG CEK + IV (I4: single IV generation point, never reused
// under the same key) → AES-256-GCM / SM4-GCM full-body encryption (cipher = ciphertext‖tag)
// → DEK payload alg$key$iv wrapped by RSA-OAEP (explicit dual SHA-256 + empty label) / SM2(C1C3C2)
// → wire body {"encrypted":"<base64url>"}, directive header x-wop-encrypt: L2;dek=<base64url>
var l2 = client.BuildRequest("POST", "/api/v1/transfer", secretBody, SecurityLevel.L2);

// Verify gateway responses (F6 fixed order: verify signature → digest recheck → DEK unwrap
// → alg family compare → bulk decrypt)
VerifyResult r = client.VerifyResponse("POST", "/api/v1/transfer", responseHeaders, responseBody);

// Verify platform callbacks (canonical URI = callback URL path, method is always POST)
VerifyResult c = client.VerifyCallback(callbackUrl, headersFromBody, rawBody);
```

Error handling (I7 fuzzing discipline):
- **Explicit** (programmable self-checks): config `CONFIG`, suite parsing `SUITE_PARSE`/`SUITE_UNSUPPORTED`,
  protocol format `PROTOCOL`, digest mismatch `DIGEST_MISMATCH`, cross-family dek alg `ALG_MISMATCH`
- **Fuzzy** (oracle-proof, fixed messages with no cause details): verification `VERIFY_FAILED`
  ("签名验证失败" / signature verification failed), decryption `DECRYPT_FAILED` ("解密失败" /
  decryption failed) — GCM tag failure / wrong key / DEK unwrap failure share one message

## Vector Self-Test (conformance)

Tests consume the same golden-vector copy as gateway CI
(`tests/Wop.Sdk.Tests/fixtures/crypto-vectors.json`, do not modify):

```bash
export PATH="$HOME/.dotnet:$PATH"
dotnet test /p:CollectCoverage=true /p:Threshold=98 '/p:ThresholdType="line,branch"'
```

Coverage:
- Positive vectors **byte-exact**: digest, AES-256-GCM / SM4-GCM (fixed key/iv),
  RSA3072/4096 signatures, SM2 sign & encrypt (fixed-k outputs match vectors byte-for-byte),
  OAEP unwrap, SM2 decrypt
- Negative vectors all rejected: tampering, 63/65-byte signatures, base64url with `=`,
  cross-family digest/dek, C1C2C3-ordered ciphertext, MGF1-SHA1 trap (OAEP dual SHA-256 pin),
  DER signatures, off-curve public points
- Coverage gate: line + branch ≥ 98%
