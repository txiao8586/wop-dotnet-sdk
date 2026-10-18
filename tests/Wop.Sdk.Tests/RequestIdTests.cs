using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Wop.Sdk;
using Xunit;

public class RequestIdTests
{
    static readonly Lazy<JsonElement> Vectors = new(() =>
        JsonDocument.Parse(File.OpenRead(
            Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json"))).RootElement);

    /// <summary>RSA-2048 真源向量密钥（fixture keys.rsa2048，PKCS#8 / SPKI 标准 Base64 单行）。</summary>
    static (string Priv, string Pub) Rsa2048Material()
    {
        var k = Vectors.Value.GetProperty("keys").GetProperty("rsa2048");
        return (k.GetProperty("privatePkcs8B64").GetString()!, k.GetProperty("publicSpkiB64").GetString()!);
    }

    static WopClient Rsa2048Client()
    {
        var (priv, pub) = Rsa2048Material();
        return WopClient.Builder()
            .AppKey("demo-app").Suite("WOP-RSA2048-SHA256")
            .MerchantPrivateKey(priv).PlatformPublicKey(pub)
            .WithClock(() => 1724900000000)
            .WithNonce(() => "nonce-001")
            .Build();
    }

    static WopClient Rsa3072Client()
    {
        using var rsa = RSA.Create(3072);
        return WopClient.Builder()
            .AppKey("demo-app").Suite("WOP-RSA3072-SHA256")
            .MerchantPrivateKey(Convert.ToBase64String(rsa.ExportPkcs8PrivateKey()))
            .PlatformPublicKey(Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()))
            .WithClock(() => 1724900000000)
            .WithNonce(() => "nonce-001")
            .Build();
    }

    // ==================== RSA2048 套件（crypto-spec E1 扩展位，默认支持） ====================

    [Fact]
    public void Rsa2048_套件默认支持_签名定长256B()
    {
        var s = AlgorithmSuite.Parse("WOP-RSA2048-SHA256");
        Assert.Equal(SuiteFamily.Rsa, s.Family);
        Assert.Equal(2048, s.KeyBits);
        Assert.Equal(256, s.SignatureLength);
        Assert.Equal("sha-256", s.DigestTag);
        Assert.Equal("AES-256-GCM", s.MessageAlgorithm);
        Assert.Equal("RSA-2048-OAEP", s.KeyWrapAlgorithm);
    }

    [Fact]
    public void Rsa2048_端到端构建与验签()
    {
        var client = Rsa2048Client();
        var draft = client.BuildRequest("POST", "/p", "{\"k\":1}"u8.ToArray(), SecurityLevel.L2, "req-001");
        Assert.Equal("req-001", draft.Headers[WopHeaders.RequestId]);
        // L2 信封出向可经自身客户端解包验证（2048 位密钥全链路）
        var result = client.VerifyResponse("POST", "/p", draft.Headers, draft.WireBody!);
        Assert.True(result.Ok, result.Reason);
    }

    // ==================== x-wop-request-id（wop-specs 附录 I） ====================

    [Fact]
    public void 显式传值_trim后原值上行_禁止改写()
    {
        var client = Rsa3072Client();
        var draft = client.BuildRequest("GET", "/p", null, SecurityLevel.L0, "  req-001  ");
        Assert.Equal("req-001", draft.Headers[WopHeaders.RequestId]);
    }

    [Fact]
    public void 恒不入签_带与不带透传头签名同值_附录I_I1()
    {
        var client = Rsa3072Client();
        var withId = client.BuildRequest("GET", "/p", null, SecurityLevel.L0, "req-001");
        var without = client.BuildRequest("GET", "/p", null, SecurityLevel.L0);
        var signedNames = withId.Headers[WopHeaders.Sign].Split('/')[2].Split(';');
        Assert.DoesNotContain(WopHeaders.RequestId, signedNames);
        Assert.Equal(without.Headers[WopHeaders.Sign], withId.Headers[WopHeaders.Sign]);
    }

    [Fact]
    public void 未传或空白_缺省生成UUID32_每次新鲜_附录I_I3()
    {
        var client = Rsa3072Client();
        var a = client.BuildRequest("GET", "/p", null, SecurityLevel.L0);
        Assert.Matches(new Regex("^[0-9a-f]{32}$"), a.Headers[WopHeaders.RequestId]);
        var b = client.BuildRequest("GET", "/p", null, SecurityLevel.L0);
        Assert.Matches(new Regex("^[0-9a-f]{32}$"), b.Headers[WopHeaders.RequestId]);
        Assert.NotEqual(a.Headers[WopHeaders.RequestId], b.Headers[WopHeaders.RequestId]);
        // 空格 trim 后为空 → 视为未设置，走缺省生成（\t/\n 属控制字符，trim 前扫描即拒）
        var blank = client.BuildRequest("GET", "/p", null, SecurityLevel.L0, "   ");
        Assert.Matches(new Regex("^[0-9a-f]{32}$"), blank.Headers[WopHeaders.RequestId]);
    }

    public static IEnumerable<object[]> ControlCharCases()
    {
        // \uXXXX 写法：\x 转义贪婪吞并后继十六进制位（"\x7Fb" 会解析成 U+07FB 而非 DEL+'b'）
        return new[] { "a\nb", "a\rb", "a\u0000b", "a\u007Fb", "a\tb", "\nlead", "trail\r", " \t ", "\u0000", "\u007F" }
            .Select(v => new object[] { v });
    }

    [Theory]
    [MemberData(nameof(ControlCharCases))]
    public void 控制字符_trim前原值扫描即拒_附录I_I2(string bad)
    {
        var client = Rsa3072Client();
        var ex = Assert.Throws<WopException>(() =>
            client.BuildRequest("GET", "/p", null, SecurityLevel.L0, bad));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("控制字符", ex.Message);
    }

    [Fact]
    public void 非ASCII显式值_构造期拒绝_Latin1传输层乱码防护()
    {
        var client = Rsa3072Client();
        var ex = Assert.Throws<WopException>(() =>
            client.BuildRequest("GET", "/p", null, SecurityLevel.L0, "请求-001"));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("非 ASCII", ex.Message);
        // 错误信息不得回显原值（configuration 错误仍守脱敏纪律）
        Assert.DoesNotContain("请求", ex.Message);
    }

    [Fact]
    public void 长度按_trim后UTF8字节计_附录I_I2()
    {
        var client = Rsa3072Client();
        var ok = client.BuildRequest("GET", "/p", null, SecurityLevel.L0, new string('x', 128));
        Assert.Equal(new string('x', 128), ok.Headers[WopHeaders.RequestId]);
        var ex129 = Assert.Throws<WopException>(() =>
            client.BuildRequest("GET", "/p", null, SecurityLevel.L0, new string('x', 129)));
        Assert.Contains("实际 129", ex129.Message);
        // CJK 现按非 ASCII 构造期拒（I2），长度路径仅对 ASCII 显式值可达
        var cjk = Assert.Throws<WopException>(() =>
            client.BuildRequest("GET", "/p", null, SecurityLevel.L0, new string('标', 42)));
        Assert.Contains("非 ASCII", cjk.Message);
    }

    [Fact]
    public void 日志义务_出向构造点打印最终头值_附录I_I3()
    {
        var client = Rsa3072Client();
        string? captured = null;
        var prev = WopClient.OutboundLogger;
        WopClient.OutboundLogger = line => captured = line;
        try
        {
            client.BuildRequest("GET", "/p", null, SecurityLevel.L0, "logreq001");
        }
        finally
        {
            WopClient.OutboundLogger = prev;
        }
        Assert.NotNull(captured);
        Assert.Contains(WopHeaders.RequestId + "=logreq001 GET /p", captured);
    }

    [Fact]
    public void 注入生成器后_Execute路径透传_附录I_I3()
    {
        var client = Rsa3072Client();
        var prev = RequestId.Generator;
        RequestId.Generator = () => "gen-anchor-001";
        try
        {
            var draft = client.BuildRequest("POST", "/p", "{}"u8.ToArray(), SecurityLevel.L0);
            Assert.Equal("gen-anchor-001", draft.Headers[WopHeaders.RequestId]);
        }
        finally
        {
            RequestId.Generator = prev;
        }
    }

    [Theory]
    [InlineData(SecurityLevel.L0)]
    [InlineData(SecurityLevel.L2)]
    public void L0_L2_双级别_头恒存在且不入签名集合_附录I_I1_I3(SecurityLevel level)
    {
        var client = Rsa2048Client();
        var body = System.Text.Encoding.UTF8.GetBytes("{\"secret\":true}");
        var draft = client.BuildRequest("POST", "/p", body, level);
        Assert.False(string.IsNullOrEmpty(draft.Headers[WopHeaders.RequestId]));
        var signedNames = draft.Headers[WopHeaders.Sign].Split('/')[2].Split(';');
        Assert.DoesNotContain(WopHeaders.RequestId, signedNames);
    }

}
