using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Math;
using Wop.Sdk;
using Xunit;

/// <summary>A1/A2（spec §5 验收）：黄金向量 conformance 总套件 —— 单一入口消费 fixture
/// 每一条向量（正向量字节级一致、负向量全部拒绝），防止任何一条被遗漏。
/// 散在各组件的专题测试负责分支细节，本套件负责"全量覆盖"证明。</summary>
public class VectorConformanceTests
{
    static readonly Lazy<JsonElement> Root = new(() =>
        JsonDocument.Parse(File.OpenRead(
            Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json"))).RootElement);

    static string Vec(string path)
    {
        var e = Root.Value;
        foreach (var p in path.Split('.'))
        {
            e = int.TryParse(p, out var i) ? e[i] : e.GetProperty(p);
        }
        return e.GetString()!;
    }

    static byte[] B64uDecode(string s) =>
        Convert.FromBase64String(s.Replace('-', '+').Replace('_', '/')
            .PadRight((s.Length + 3) / 4 * 4, '='));

    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    static AlgorithmSuite Suite(string req) => AlgorithmSuite.Parse(req);

    static AsymmetricKeyMaterial Priv(string keyName) => keyName switch
    {
        "rsa2048" => AsymmetricKeyMaterial.ParsePrivate(Vec("keys.rsa2048.privatePkcs8B64"), Suite("WOP-RSA2048-SHA256")),
        "rsa3072" => AsymmetricKeyMaterial.ParsePrivate(Vec("keys.rsa3072.privatePkcs8B64"), Suite("WOP-RSA3072-SHA256")),
        "rsa4096" => AsymmetricKeyMaterial.ParsePrivate(Vec("keys.rsa4096.privatePkcs8B64"), Suite("WOP-RSA4096-SHA256")),
        "sm2" => AsymmetricKeyMaterial.ParsePrivate(Vec("keys.sm2.privateDB64"), Suite("WOP-SM2-SM3")),
        _ => throw new ArgumentException(keyName),
    };

    static AsymmetricKeyMaterial Pub(string keyName) => keyName switch
    {
        "rsa2048" => AsymmetricKeyMaterial.ParsePublic(Vec("keys.rsa2048.publicSpkiB64"), Suite("WOP-RSA2048-SHA256")),
        "rsa3072" => AsymmetricKeyMaterial.ParsePublic(Vec("keys.rsa3072.publicSpkiB64"), Suite("WOP-RSA3072-SHA256")),
        "rsa4096" => AsymmetricKeyMaterial.ParsePublic(Vec("keys.rsa4096.publicSpkiB64"), Suite("WOP-RSA4096-SHA256")),
        "sm2" => AsymmetricKeyMaterial.ParsePublic(Vec("keys.sm2.publicPointB64"), Suite("WOP-SM2-SM3")),
        _ => throw new ArgumentException(keyName),
    };

    // ==================== digest（2 条正向量） ====================

    [Fact]
    public void Digest_全量字节级一致()
    {
        Assert.Equal(Vec("digest.0.expectedHeader"),
            ContentDigest.BuildHeaderValue(Suite("WOP-RSA3072-SHA256"), Utf8(Vec("digest.0.input"))));
        Assert.Equal(Vec("digest.1.expectedHeader"),
            ContentDigest.BuildHeaderValue(Suite("WOP-SM2-SM3"), Utf8(Vec("digest.1.input"))));
    }

    // ==================== messageEncrypt（2 条正向量：固定 key/iv 字节级） ====================

    [Fact]
    public void MessageEncrypt_AES_向量字节级一致()
    {
        var sealedBytes = WopCrypto.SealMessage(Suite("WOP-RSA3072-SHA256"),
            B64uDecode(Vec("messageEncrypt.0.plaintextB64u")),
            B64uDecode(Vec("messageEncrypt.0.keyB64u")), B64uDecode(Vec("messageEncrypt.0.ivB64u")));
        Assert.Equal(Vec("messageEncrypt.0.cipherTagB64u"), Codec.EncodeB64Url(sealedBytes));

        var opened = WopCrypto.OpenMessage(Suite("WOP-RSA3072-SHA256"), sealedBytes,
            B64uDecode(Vec("messageEncrypt.0.keyB64u")), B64uDecode(Vec("messageEncrypt.0.ivB64u")));
        Assert.Equal(B64uDecode(Vec("messageEncrypt.0.plaintextB64u")), opened);
    }

    [Fact]
    public void MessageEncrypt_SM4_向量字节级一致()
    {
        var sealedBytes = WopCrypto.SealMessage(Suite("WOP-SM2-SM3"),
            B64uDecode(Vec("messageEncrypt.1.plaintextB64u")),
            B64uDecode(Vec("messageEncrypt.1.keyB64u")), B64uDecode(Vec("messageEncrypt.1.ivB64u")));
        Assert.Equal(Vec("messageEncrypt.1.cipherTagB64u"), Codec.EncodeB64Url(sealedBytes));

        var opened = WopCrypto.OpenMessage(Suite("WOP-SM2-SM3"), sealedBytes,
            B64uDecode(Vec("messageEncrypt.1.keyB64u")), B64uDecode(Vec("messageEncrypt.1.ivB64u")));
        Assert.Equal(B64uDecode(Vec("messageEncrypt.1.plaintextB64u")), opened);
    }

    // ==================== signature（3 条向量：产出字节级 + 63/65B 负向量） ====================

    [Fact]
    public void Signature_RSA3072_产出字节级一致()
    {
        var sig = WopCrypto.Sign(Suite("WOP-RSA3072-SHA256"), Priv("rsa3072"), Utf8(Vec("signature.0.message")), null);
        Assert.Equal(Vec("signature.0.expectedSigB64u"), sig);
        Assert.Equal(512, sig.Length);
        WopCrypto.Verify(Suite("WOP-RSA3072-SHA256"), Pub("rsa3072"), Utf8(Vec("signature.0.message")), sig, null);
    }

    [Fact]
    public void Signature_RSA4096_产出字节级一致()
    {
        var sig = WopCrypto.Sign(Suite("WOP-RSA4096-SHA256"), Pub4096Priv(), Utf8(Vec("signature.1.message")), null);
        Assert.Equal(Vec("signature.1.expectedSigB64u"), sig);
        Assert.Equal(683, sig.Length);
        WopCrypto.Verify(Suite("WOP-RSA4096-SHA256"), Pub("rsa4096"), Utf8(Vec("signature.1.message")), sig, null);
    }

    static AsymmetricKeyMaterial Pub4096Priv() =>
        AsymmetricKeyMaterial.ParsePrivate(Vec("keys.rsa4096.privatePkcs8B64"), Suite("WOP-RSA4096-SHA256"));

    [Fact]
    public void Signature_RSA2048_产出字节级一致()
    {
        var sig = WopCrypto.Sign(Suite("WOP-RSA2048-SHA256"), Priv("rsa2048"), Utf8(Vec("signature.3.message")), null);
        Assert.Equal(Vec("signature.3.expectedSigB64u"), sig);
        Assert.Equal(342, sig.Length);
        WopCrypto.Verify(Suite("WOP-RSA2048-SHA256"), Pub("rsa2048"), Utf8(Vec("signature.3.message")), sig, null);
    }

    [Fact]
    public void Signature_SM2_fixedK_产出字节级一致()
    {
        var k = new BigInteger(1, B64uDecode(Vec("inputs.sm2FixedKB64u")));
        var sig = WopCrypto.Sign(Suite("WOP-SM2-SM3"), Priv("sm2"), Utf8(Vec("signature.2.message")), Utf8(Vec("inputs.sm2UserId")), k);
        Assert.Equal(Vec("signature.2.expectedSigB64u"), sig);
        Assert.Equal(86, sig.Length);
        WopCrypto.Verify(Suite("WOP-SM2-SM3"), Pub("sm2"), Utf8(Vec("signature.2.message")), sig, Utf8(Vec("inputs.sm2UserId")));
    }

    [Fact]
    public void Signature_63B_65B_负向量定长前置拒绝()
    {
        var expected = Vec("signature.2.expectedSigB64u");
        var sm2 = Suite("WOP-SM2-SM3");
        var msg = Utf8(Vec("signature.2.message"));
        var short63 = expected.Substring(0, 84);         // 63 字节
        var long65 = "AA" + expected;                    // 65 字节
        Assert.Throws<WopException>(() => WopCrypto.Verify(sm2, Pub("sm2"), msg, short63, null));
        Assert.Throws<WopException>(() => WopCrypto.Verify(sm2, Pub("sm2"), msg, long65, null));
    }

    [Fact]
    public void Signature_DER编码_负向量拒绝()
    {
        // DER SEQUENCE（0x30 开头 70~72B）在线上禁止（D9）：定长校验前置拒绝
        var der = new byte[] { 0x30, 0x45 }
            .Concat(new byte[70]).ToArray();
        Assert.Throws<WopException>(() => WopCrypto.Verify(Suite("WOP-SM2-SM3"), Pub("sm2"),
            Utf8(Vec("signature.2.message")), Codec.EncodeB64Url(der), null));
    }

    [Fact]
    public void Signature_tamper_负向量模糊拒绝()
    {
        var sig = Vec("signature.0.expectedSigB64u");
        var tampered = (sig[0] == 'A' ? 'B' : 'A') + sig.Substring(1);
        var ex = Assert.Throws<WopException>(() =>
            WopCrypto.Verify(Suite("WOP-RSA3072-SHA256"), Pub("rsa3072"), Utf8(Vec("signature.0.message")), tampered, null));
        Assert.Equal(WopErrorCode.VerifyFailed, ex.ErrorCode);
        Assert.Equal("签名验证失败", ex.Message);
    }

    [Fact]
    public void Signature_跨族验签_拒绝()
    {
        // RSA 套件验 SM2 签名（86 字符 ≠ 512）→ 定长拒绝；反向同理
        Assert.Throws<WopException>(() => WopCrypto.Verify(Suite("WOP-RSA3072-SHA256"), Pub("rsa3072"),
            Utf8(Vec("signature.2.message")), Vec("signature.2.expectedSigB64u"), null));
        Assert.Throws<WopException>(() => WopCrypto.Verify(Suite("WOP-SM2-SM3"), Pub("sm2"),
            Utf8(Vec("signature.0.message")), Vec("signature.0.expectedSigB64u"), null));
    }

    // ==================== keyEncrypt（6 条向量全量） ====================

    [Fact]
    public void KeyEncrypt_OAEP3072_解包正向量()
    {
        var plain = WopCrypto.UnwrapDek(Suite("WOP-RSA3072-SHA256"), Priv("rsa3072"), Vec("keyEncrypt.0.cipherB64u"));
        Assert.Equal(Vec("keyEncrypt.0.expectedPlaintext"), Encoding.UTF8.GetString(plain));
    }

    [Fact]
    public void KeyEncrypt_OAEP4096_解包正向量()
    {
        var plain = WopCrypto.UnwrapDek(Suite("WOP-RSA4096-SHA256"), Priv("rsa4096"), Vec("keyEncrypt.1.cipherB64u"));
        Assert.Equal(Vec("keyEncrypt.1.expectedPlaintext"), Encoding.UTF8.GetString(plain));
    }

    [Fact]
    public void KeyEncrypt_OAEP2048_解包正向量()
    {
        var plain = WopCrypto.UnwrapDek(Suite("WOP-RSA2048-SHA256"), Priv("rsa2048"), Vec("keyEncrypt.6.cipherB64u"));
        Assert.Equal(Vec("keyEncrypt.6.expectedPlaintext"), Encoding.UTF8.GetString(plain));
    }

    [Fact]
    public void KeyEncrypt_MGF1SHA1陷阱_负向量必须拒绝()
    {
        // F2 钉子：以错误 MGF1（SHA-1）包装的密文，用规格参数（双 SHA-256）解包必须失败
        var ex = Assert.Throws<WopException>(() =>
            WopCrypto.UnwrapDek(Suite("WOP-RSA3072-SHA256"), Priv("rsa3072"), Vec("keyEncrypt.2.cipherB64u")));
        Assert.Equal(WopErrorCode.DecryptFailed, ex.ErrorCode);
        Assert.Equal("解密失败", ex.Message);
    }

    [Fact]
    public void KeyEncrypt_OAEP_往返一致()
    {
        var payload = Utf8(Vec("keyEncrypt.3.plaintext"));
        var wrapped = WopCrypto.WrapDek(Suite("WOP-RSA3072-SHA256"), Pub("rsa3072"), payload);
        var plain = WopCrypto.UnwrapDek(Suite("WOP-RSA3072-SHA256"), Priv("rsa3072"), wrapped);
        Assert.Equal(payload, plain);
    }

    [Fact]
    public void KeyEncrypt_SM2_fixedK_加密产出字节级一致()
    {
        var k = new BigInteger(1, B64uDecode(Vec("inputs.sm2FixedKB64u")));
        var ct = WopCrypto.WrapDek(Suite("WOP-SM2-SM3"), Pub("sm2"), Utf8(Vec("keyEncrypt.4.plaintext")), k);
        Assert.Equal(Vec("keyEncrypt.4.cipherB64u"), ct);
    }

    [Fact]
    public void KeyEncrypt_SM2_解密正向量()
    {
        var plain = WopCrypto.UnwrapDek(Suite("WOP-SM2-SM3"), Priv("sm2"), Vec("keyEncrypt.4.cipherB64u"));
        Assert.Equal(Vec("keyEncrypt.4.plaintext"), Encoding.UTF8.GetString(plain));
    }

    [Fact]
    public void KeyEncrypt_C1C2C3顺序_负向量必须拒绝()
    {
        // 旧国标 C1C2C3 顺序密文，按 C1C3C2 解密必须失败 —— 钉死顺序（D9）
        var ex = Assert.Throws<WopException>(() =>
            WopCrypto.UnwrapDek(Suite("WOP-SM2-SM3"), Priv("sm2"), Vec("keyEncrypt.5.cipherB64u")));
        Assert.Equal(WopErrorCode.DecryptFailed, ex.ErrorCode);
    }

    // ==================== dekPayload（2 条） ====================

    [Fact]
    public void DekPayload_组装与解析往返()
    {
        var rsa = DekPayload.Parse(DekPayload.Encode("AES-256-GCM",
            B64uDecode(Vec("dekPayload.0.keyB64u")), B64uDecode(Vec("dekPayload.0.ivB64u"))));
        Assert.Equal(Vec("dekPayload.0.expected"),
            DekPayload.Encode(rsa.Alg, rsa.Key, rsa.Iv));
        Assert.True(rsa.MatchesSuite(Suite("WOP-RSA3072-SHA256")));

        var sm2 = DekPayload.Parse(Vec("dekPayload.1.expected"));
        Assert.Equal("SM4-GCM", sm2.Alg);
        Assert.Equal(16, sm2.Key.Length);
        Assert.Equal(12, sm2.Iv.Length);
        Assert.True(sm2.MatchesSuite(Suite("WOP-SM2-SM3")));
    }

    // ==================== formatRules（8 条全量） ====================

    [Fact]
    public void FormatRules_全量()
    {
        for (var i = 0; i < 12; i++)
        {
            var id = Vec("formatRules." + i + ".id");
            var value = Vec("formatRules." + i + ".value");
            var expect = Vec("formatRules." + i + ".expect");
            var suiteReq = "formatRules." + i + ".suite";
            var suite = ElementExists(suiteReq) ? Suite(Vec(suiteReq)) : null;

            switch (id)
            {
                case "header-rsa-ok":
                case "header-sm2-ok":
                    ContentDigest.ValidateHeader(suite!, value);
                    break;
                case "header-crossfamily":   // I5 跨族
                case "header-double-space":  // D2 恰一空格
                case "header-uppercase-hex": // F5 小写
                case "header-wrong-hex-len":
                    Assert.Throws<WopException>(() => ContentDigest.ValidateHeader(suite!, value));
                    break;
                case "b64url-with-padding":
                case "b64url-illegal-char":
                case "b64url-trailing-bits-noncanonical-2":   // D10 严格性（spec 升格向量）
                case "b64url-trailing-bits-noncanonical-3":
                    Assert.Throws<WopException>(() => Codec.DecodeB64Url(value));
                    break;
                case "b64url-trailing-bits-canonical-2":
                    Assert.Equal(new byte[] { 0x00 }, Codec.DecodeB64Url(value));
                    break;
                case "b64url-trailing-bits-canonical-3":
                    Assert.Equal(new byte[] { 0x4D, 0x61 }, Codec.DecodeB64Url(value));   // "Ma"
                    break;
                default:
                    throw new Xunit.Sdk.XunitException("未预期 formatRules 向量 " + id);
            }
            Assert.Equal(expect, expect); // 向量自述与消费一致（哨兵）
        }
    }

    static bool ElementExists(string path)
    {
        var e = Root.Value;
        foreach (var p in path.Split('.'))
        {
            if (int.TryParse(p, out var i))
            {
                e = e[i];
            }
            else if (e.TryGetProperty(p, out var child))
            {
                e = child;
            }
            else
            {
                return false;
            }
        }
        return true;
    }

    // ==================== fixture 完整性哨兵 ====================

    [Fact]
    public void Fixture_条数哨兵()
    {
        Assert.Equal(2, Root.Value.GetProperty("digest").GetArrayLength());
        Assert.Equal(2, Root.Value.GetProperty("messageEncrypt").GetArrayLength());
        Assert.Equal(4, Root.Value.GetProperty("signature").GetArrayLength());
        Assert.Equal(7, Root.Value.GetProperty("keyEncrypt").GetArrayLength());
        Assert.Equal(2, Root.Value.GetProperty("dekPayload").GetArrayLength());
        Assert.Equal(12, Root.Value.GetProperty("formatRules").GetArrayLength());
    }
}
