using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Security;
using Wop.Sdk;
using Xunit;

// interop conformance（协议编排跨仓一致性合同消费端，spec:interop-v1）：
// fixture 为 wop-specs/interop/v1/interop-cases.json 的字节副本（禁手改，sha256 钉死）。
// build 方向断言"同输入复现同 draft"（byte-exact 全量 / deterministic-fields 按 opaque
// 剥离密钥参与段后比对）；verify 方向断言跨仓编排与错误分类合同
// （positive 明文一致，negative 逐条对账 canonical class）。
public class InteropConformanceTests
{
    // 真源 sha256（wop-specs/interop/v1/interop-cases.json，2026-09-02 冻结，30 条含 n17）
    const string FixtureSha256 = "c920ca1a93ccb3899a659f59fed6ec4652cf9e1b3b58bbdac23c45ac3ed2353e";

    static readonly Lazy<byte[]> FixtureBytes = new(() => File.ReadAllBytes(
        Path.Combine(AppContext.BaseDirectory, "fixtures", "interop-cases.json")));

    static readonly Lazy<InteropFixture> Fixture = new(
        () => JsonSerializer.Deserialize<InteropFixture>(FixtureBytes.Value)!);

    static readonly Lazy<JsonElement> Keys = new(() => JsonDocument.Parse(File.OpenRead(
        Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json")))
        .RootElement.GetProperty("keys"));

    static string K(string name, string field) =>
        Keys.Value.GetProperty(name).GetProperty(field).GetString()!;

    // ==================== fixture 完整性（消费口径 1 + 4：sha256 一致 + 哨兵） ====================

    [Fact]
    public void Fixture_真源字节副本_sha256一致()
    {
        // spec:interop-v1 字节副本进仓，与真源 sha256 逐位一致（禁手改防漂移）
        Assert.Equal(FixtureSha256, Codec.LowerHex(SHA256.HashData(FixtureBytes.Value)));
    }

    [Fact]
    public void Fixture_哨兵_格式条数与已知id()
    {
        var f = Fixture.Value;
        Assert.Equal("wop-interop-1", f.Meta!.Format);
        Assert.Equal(30, f.Meta.CaseCount);
        Assert.Equal(30, f.Cases!.Count);
        Assert.Equal(6, f.Cases.Count(c => c.Kind == "build"));
        Assert.Equal(7, f.Cases.Count(c => c.Kind == "verify-positive"));
        Assert.Equal(17, f.Cases.Count(c => c.Kind == "verify-negative"));
        // 已知 id 哨兵：集合恰为已知 30 条（fixture 漂移 / 新增未登记用例即失败）
        Assert.Equal(KnownIds(), new HashSet<string>(f.Cases.Select(c => c.Id)));
    }

    // ==================== build 方向（消费口径 2：同输入复现同 draft） ====================

    [Fact]
    public void Build_同输入复现同draft_按reproduceMode比对()
    {
        var builds = 0;
        foreach (var c in Fixture.Value.Cases!)
        {
            if (c.Kind != "build")
            {
                continue;
            }
            builds++;
            var client = ClientFor(c, new HexStreamRandom(Convert.FromHexString(c.Input!.RandomHex)));
            var draft = client.BuildRequest(c.Input.Method, c.Input.Path,
                B64uDecode(c.Input.PlaintextB64),
                c.Level == "L2" ? SecurityLevel.L2 : SecurityLevel.L0);

            Assert.NotNull(draft.WireBody);
            Assert.Equal(c.Expected!.WireBodyB64, Codec.EncodeB64Url(draft.WireBody));

            // byte-exact：全量字节级；deterministic-fields：opaque 声明的密钥参与段
            // （SM2 签名 k / 包装 k）剥离后，其余头与 wire body 仍字节级比对
            var opaque = new HashSet<string>(c.Expected.Opaque);
            foreach (var (name, wantRaw) in c.Expected.Headers)
            {
                Assert.True(draft.Headers.ContainsKey(name), c.Id + ": 缺头 " + name);
                var got = draft.Headers[name];
                var want = wantRaw;
                if (opaque.Contains(name + ".signatureSegment") && name == WopHeaders.Sign)
                {
                    (got, want) = (StripSignatureSegment(got), StripSignatureSegment(want));
                }
                if (opaque.Contains(name + ".dekValue") && name == WopHeaders.Encrypt)
                {
                    (got, want) = (StripDekValue(got), StripDekValue(want));
                }
                Assert.Equal(want, got);
            }
            // x-wop-request-id 是规格附录 I 的可选透传头（恒不入签、网关日志关联用），
            // 不属于 interop 冻结的协议头合同（fixture sha256 钉死不可改），比对前剥离
            var protocolHeaderCount = draft.Headers.Count - (draft.Headers.ContainsKey(WopHeaders.RequestId) ? 1 : 0);
            Assert.Equal(c.Expected.Headers.Count, protocolHeaderCount);
        }
        Assert.Equal(6, builds);
    }

    // ==================== verify 方向（消费口径 3：positive 明文一致 / negative 分类对账） ====================

    [Fact]
    public void Verify_正向_通过且明文一致()
    {
        var pos = 0;
        foreach (var c in Cases("verify-positive"))
        {
            pos++;
            var result = VerifyCase(c);
            Assert.True(result.Ok, c.Id + ": 应通过（" + result.ErrorCode + " " + result.Reason + "）");
            Assert.Equal(B64uDecode(c.Expect!.PlaintextB64!), result.Plaintext);
        }
        Assert.Equal(7, pos);
    }

    [Fact]
    public void Verify_负向_错误分类逐条对账()
    {
        var neg = 0;
        foreach (var c in Cases("verify-negative"))
        {
            neg++;
            var result = VerifyCase(c);
            Assert.False(result.Ok, c.Id + ": 应拒绝");
            var gotClass = ClassOf(result.ErrorCode);
            Assert.True(gotClass == c.Expect!.ErrorClass,
                c.Id + ": 错误分类 = " + gotClass + "（" + result.ErrorCode + "），应为 " + c.Expect.ErrorClass);
        }
        Assert.Equal(17, neg);
    }

    /// <summary>本仓错误码 → 跨仓 canonical class 显式映射表
    /// （wop-specs/interop/v1 错误分类合同；verify/decrypt 模糊，其余明确）。</summary>
    static string ClassOf(WopErrorCode? code) => code switch
    {
        WopErrorCode.VerifyFailed => "verify-failed",
        WopErrorCode.DecryptFailed => "decrypt-failed",
        WopErrorCode.DigestMismatch => "digest-mismatch",
        WopErrorCode.AlgMismatch => "alg-mismatch",
        _ => "protocol",
    };

    static List<InteropCase> Cases(string kind) =>
        Fixture.Value.Cases!.Where(c => c.Kind == kind).ToList();

    static VerifyResult VerifyCase(InteropCase c)
    {
        var client = ClientFor(c);
        var verifyPath = string.IsNullOrEmpty(c.VerifyPath) ? c.Response!.Path : c.VerifyPath;
        var body = B64uDecode(c.Response!.WireBodyB64);
        return client.VerifyResponse(c.Response.Method, verifyPath, c.Response.Headers, body);
    }

    static WopClient ClientFor(InteropCase c, SecureRandom? random = null)
    {
        var (priv, pub) = KeyMaterial(c.Suite!);
        var builder = WopClient.Builder()
            .AppKey(c.Input?.AppKey ?? c.Response!.AppKey)
            .Suite(c.Suite!)
            .MerchantPrivateKey(priv)
            .PlatformPublicKey(pub);
        if (c.Input is { } input)
        {
            builder = builder.WithClock(() => input.TimestampMs).WithNonce(() => input.Nonce);
        }
        if (random != null)
        {
            builder = builder.WithRandom(random);
        }
        return builder.Build();
    }

    static (string Priv, string Pub) KeyMaterial(string suite) => suite switch
    {
        "WOP-RSA4096-SHA256" => (K("rsa4096", "privatePkcs8B64"), K("rsa4096", "publicSpkiB64")),
        "WOP-SM2-SM3" => (K("sm2", "privateDB64"), K("sm2", "publicPointB64")),
        _ => (K("rsa3072", "privatePkcs8B64"), K("rsa3072", "publicSpkiB64")),
    };

    static byte[] B64uDecode(string s) =>
        Convert.FromBase64String(s.Replace('-', '+').Replace('_', '/')
            .PadRight((s.Length + 3) / 4 * 4, '='));

    static string StripSignatureSegment(string signHeader)
    {
        var i = signHeader.LastIndexOf('/');
        return i >= 0 ? signHeader[..(i + 1)] : signHeader;
    }

    static string StripDekValue(string encryptHeader)
    {
        var i = encryptHeader.IndexOf("dek=", StringComparison.Ordinal);
        return i >= 0 ? encryptHeader[..(i + 4)] : encryptHeader;
    }

    static HashSet<string> KnownIds() => new()
    {
        // build（6：3 套件 × L0/L2）
        "build:WOP-RSA3072-SHA256:L0", "build:WOP-RSA3072-SHA256:L2",
        "build:WOP-RSA4096-SHA256:L0", "build:WOP-RSA4096-SHA256:L2",
        "build:WOP-SM2-SM3:L0", "build:WOP-SM2-SM3:L2",
        // verify-positive（7）
        "p07", "p08", "p09", "p10", "p11", "p12", "p13",
        // verify-negative（17）
        "n01-encrypted-char-damage", "n02-wire-tampered-after-signing",
        "n03-digest-tag-cross-family", "n04-dek-alg-cross-family",
        "n05-dek-c1c2c3-order", "n06-signature-b64-padding",
        "n07-signature-63b", "n08-signature-65b",
        "n09-digest-missing", "n10-digest-not-signed",
        "n11-suite-mismatch", "n12-envelope-missing-field",
        "n13-dek-key-length", "n14-missing-signed-header",
        "n15-digest-without-body", "n16-replay-cross-path",
        "n17-encrypt-missing-dek",
    };
}

/// <summary>确定性随机流（interop build 复现）：按序供给注入的 randomHex 字节。
/// 随机流消费顺序合同 [CEK][12B IV][OAEP seed / SM2 k…] 各路径经不同 NextBytes
/// 重载进入（OaepEncoding 走三参重载），三个重载必须一并覆盖。
/// 耗尽后以 0x5A 填充（正常路径确定性段恒在前段，不触末段）。</summary>
sealed class HexStreamRandom : SecureRandom
{
    private readonly byte[] _stream;
    private int _pos;

    internal HexStreamRandom(byte[] stream) => _stream = stream;

    public override void NextBytes(byte[] bytes) => Fill(bytes, 0, bytes.Length);

    public override void NextBytes(byte[] bytes, int off, int len) => Fill(bytes, off, len);

    public override void NextBytes(Span<byte> buffer) => Fill(buffer);

    private void Fill(byte[] bytes, int off, int len)
    {
        for (var i = off; i < off + len; i++)
        {
            bytes[i] = _pos < _stream.Length ? _stream[_pos++] : (byte)0x5A;
        }
    }

    private void Fill(Span<byte> bytes)
    {
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = _pos < _stream.Length ? _stream[_pos++] : (byte)0x5A;
        }
    }
}

// ==================== fixture DTO（wop-interop-1 格式，与真源字段一一对应） ====================

sealed class InteropFixture
{
    [JsonPropertyName("_meta")] public InteropMeta? Meta { get; set; }
    [JsonPropertyName("cases")] public List<InteropCase>? Cases { get; set; }
}

sealed class InteropMeta
{
    [JsonPropertyName("format")] public string Format { get; set; } = null!;
    [JsonPropertyName("caseCount")] public int CaseCount { get; set; }
}

sealed class InteropCase
{
    [JsonPropertyName("id")] public string Id { get; set; } = null!;
    [JsonPropertyName("kind")] public string Kind { get; set; } = null!;
    [JsonPropertyName("suite")] public string? Suite { get; set; }
    [JsonPropertyName("level")] public string? Level { get; set; }
    [JsonPropertyName("input")] public InteropInput? Input { get; set; }
    [JsonPropertyName("expected")] public InteropExpected? Expected { get; set; }
    [JsonPropertyName("response")] public InteropResponse? Response { get; set; }
    [JsonPropertyName("verifyPath")] public string? VerifyPath { get; set; }
    [JsonPropertyName("expect")] public InteropExpect? Expect { get; set; }
}

sealed class InteropInput
{
    [JsonPropertyName("method")] public string Method { get; set; } = null!;
    [JsonPropertyName("path")] public string Path { get; set; } = null!;
    [JsonPropertyName("appKey")] public string AppKey { get; set; } = null!;
    [JsonPropertyName("plaintextB64")] public string PlaintextB64 { get; set; } = null!;
    [JsonPropertyName("timestampMs")] public long TimestampMs { get; set; }
    [JsonPropertyName("nonce")] public string Nonce { get; set; } = null!;
    [JsonPropertyName("randomHex")] public string RandomHex { get; set; } = null!;
}

sealed class InteropExpected
{
    [JsonPropertyName("reproduceMode")] public string ReproduceMode { get; set; } = null!;
    [JsonPropertyName("wireBodyB64")] public string WireBodyB64 { get; set; } = null!;
    [JsonPropertyName("headers")] public Dictionary<string, string> Headers { get; set; } = null!;
    [JsonPropertyName("opaque")] public List<string> Opaque { get; set; } = new();
}

sealed class InteropResponse
{
    [JsonPropertyName("method")] public string Method { get; set; } = null!;
    [JsonPropertyName("path")] public string Path { get; set; } = null!;
    [JsonPropertyName("appKey")] public string AppKey { get; set; } = null!;
    [JsonPropertyName("headers")] public Dictionary<string, string> Headers { get; set; } = null!;
    [JsonPropertyName("wireBodyB64")] public string WireBodyB64 { get; set; } = null!;
}

sealed class InteropExpect
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("plaintextB64")] public string? PlaintextB64 { get; set; }
    [JsonPropertyName("errorClass")] public string? ErrorClass { get; set; }
}
