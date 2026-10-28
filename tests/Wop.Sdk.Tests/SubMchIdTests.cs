using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Wop.Sdk;
using Xunit;

public class SubMchIdTests
{
    static WopClient Client() => WopClientTests.RsaBuilder().Build();

    static string[] SignedNames(RequestDraft draft) =>
        SignHeader.Parse(draft.Headers[WopHeaders.Sign]).SignedHeaders.ToArray();

    static void AssertSignatureValid(WopClient client, RequestDraft draft)
    {
        var parsed = SignHeader.Parse(draft.Headers[WopHeaders.Sign]);
        var map = parsed.SignedHeaders.ToDictionary(n => n, n => draft.Headers[n], StringComparer.Ordinal);
        var canonical = CanonicalRequest.Build(parsed.AuthString, draft.Method, draft.Path, "",
            CanonicalRequest.CanonicalHeaders(map));
        // D14：出向签名 userId = appKey 字节
        WopCrypto.Verify(client.Suite, WopClientTests.RespPubMaterial(client.Suite),
            Encoding.UTF8.GetBytes(canonical), parsed.Signature, Encoding.UTF8.GetBytes("demo-app"));
    }

    // ==================== 入签位置与签名正确性 ====================

    [Fact]
    public void 子商户头_签名前写入_入签且签名可验()
    {
        var client = Client();
        var draft = client.BuildRequest("POST", "/api/pay", Encoding.UTF8.GetBytes("{\"k\":1}"),
            SecurityLevel.L0, "req-001", "PLF-SUB-001");

        Assert.Equal("PLF-SUB-001", draft.Headers[WopHeaders.SubMchId]);
        Assert.Equal(
            new[] { "x-wop-appkey", "x-wop-content-digest", "x-wop-nonce", "x-wop-sub-mch-id", "x-wop-timestamp" },
            SignedNames(draft));
        Assert.DoesNotContain(WopHeaders.RequestId, SignedNames(draft));
        AssertSignatureValid(client, draft);
    }

    [Fact]
    public void 子商户头_无body_L0_仍入签()
    {
        var client = Client();
        var draft = client.BuildRequest("GET", "/api/query", null, SecurityLevel.L0, null, "PLF-SUB-001");

        Assert.Equal(
            new[] { "x-wop-appkey", "x-wop-nonce", "x-wop-sub-mch-id", "x-wop-timestamp" },
            SignedNames(draft));
        AssertSignatureValid(client, draft);
    }

    [Fact]
    public void 子商户头_L2_与digest_encrypt共存入签()
    {
        var client = Client();
        var draft = client.BuildRequest("POST", "/api/transfer", Encoding.UTF8.GetBytes("{\"amount\":1}"),
            SecurityLevel.L2, null, "PLF-SUB-001");

        Assert.Equal(
            new[] { "x-wop-appkey", "x-wop-content-digest", "x-wop-encrypt", "x-wop-nonce", "x-wop-sub-mch-id", "x-wop-timestamp" },
            SignedNames(draft));
        AssertSignatureValid(client, draft);
    }

    [Fact]
    public void 子商户头_首尾空白_trim后上行()
    {
        var draft = Client().BuildRequest("GET", "/p", null, SecurityLevel.L0, null, "  PLF-SUB-001  ");
        Assert.Equal("PLF-SUB-001", draft.Headers[WopHeaders.SubMchId]);
    }

    // ==================== AC-20 零回归 ====================

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void 子商户头_未传或空白_L0_头缺席且签名逐字节同旧行为_AC20(string? subMchId)
    {
        var client = Client();
        var body = Encoding.UTF8.GetBytes("{\"k\":1}");
        var baseline = client.BuildRequest("POST", "/api/pay", body, SecurityLevel.L0, "req-001");
        var draft = client.BuildRequest("POST", "/api/pay", body, SecurityLevel.L0, "req-001", subMchId);

        Assert.False(draft.Headers.ContainsKey(WopHeaders.SubMchId));
        Assert.Equal(baseline.Headers.Count, draft.Headers.Count);
        foreach (var (name, value) in baseline.Headers)
        {
            Assert.Equal(value, draft.Headers[name]);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void 子商户头_未传或空白_L2_头缺席且签名逐字节同旧行为_AC20(string? subMchId)
    {
        // L2 含 CSPRNG CEK/IV：注入同序列随机流后，未携带子商户身份的出向字节应与旧行为逐字节一致
        var body = Encoding.UTF8.GetBytes("{\"amount\":1}");
        RequestDraft Build(string? id, SecureRandom random) => WopClientTests.RsaBuilder()
            .WithClock(() => 1774340000000)
            .WithNonce(() => "l2-nonce-deterministic")
            .WithRandom(random)
            .Build()
            .BuildRequest("POST", "/api/transfer", body, SecurityLevel.L2, null, id);

        var baseline = Build(null, new SeqRandom());
        var draft = Build(subMchId, new SeqRandom());

        Assert.False(draft.Headers.ContainsKey(WopHeaders.SubMchId));
        Assert.Equal(baseline.Headers[WopHeaders.Sign], draft.Headers[WopHeaders.Sign]);
        Assert.Equal(baseline.Headers[WopHeaders.Encrypt], draft.Headers[WopHeaders.Encrypt]);
        Assert.Equal(baseline.WireBody, draft.WireBody);
    }

    /// <summary>确定性顺序流：第 n 字节 = (n*7+1) &amp; 0xFF（与 MutationKillBoundaryTests 同构）。</summary>
    sealed class SeqRandom : SecureRandom
    {
        private byte _n;

        private void Fill(byte[] buffer)
        {
            for (var i = 0; i < buffer.Length; i++)
            {
                buffer[i] = (byte)(_n++ * 7 + 1);
            }
        }

        public override void NextBytes(byte[] bytes) => Fill(bytes);

        public override void NextBytes(Span<byte> buffer)
        {
            var tmp = new byte[buffer.Length];
            Fill(tmp);
            tmp.CopyTo(buffer);
        }
    }

    // ==================== 校验边界 ====================

    [Fact]
    public void 子商户头_长度128允许_129拒绝()
    {
        var client = Client();
        var ok = client.BuildRequest("GET", "/p", null, SecurityLevel.L0, null, new string('a', 128));
        Assert.Equal(new string('a', 128), ok.Headers[WopHeaders.SubMchId]);

        var ex = Assert.Throws<WopException>(() =>
            client.BuildRequest("GET", "/p", null, SecurityLevel.L0, null, new string('a', 129)));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("实际 129", ex.Message);
    }

    public static IEnumerable<object[]> ControlCharCases()
    {
        return new[] { "a\nb", "a\rb", "a\u0000b", "a\tb", "\tsub", "sub\t", "a\u007Fb" }
            .Select(v => new object[] { v });
    }

    [Theory]
    [MemberData(nameof(ControlCharCases))]
    public void 子商户头_控制字符_trim前原值扫描即拒(string bad)
    {
        var ex = Assert.Throws<WopException>(() =>
            Client().BuildRequest("GET", "/p", null, SecurityLevel.L0, null, bad));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("可打印 ASCII", ex.Message);
    }

    [Fact]
    public void 子商户头_非ASCII拒绝_错误不回显原值()
    {
        var ex = Assert.Throws<WopException>(() =>
            Client().BuildRequest("GET", "/p", null, SecurityLevel.L0, null, "PLF中文"));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("可打印 ASCII", ex.Message);
        Assert.DoesNotContain("中文", ex.Message);
    }

    [Theory]
    [InlineData("PLF SUB")]
    [InlineData("PLF  SUB")]
    public void 子商户头_内部空白拒绝(string bad)
    {
        var ex = Assert.Throws<WopException>(() =>
            Client().BuildRequest("GET", "/p", null, SecurityLevel.L0, null, bad));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("内部空白", ex.Message);
    }

    [Fact]
    public void 子商户头_可打印ASCII边界_允许()
    {
        var draft = Client().BuildRequest("GET", "/p", null, SecurityLevel.L0, null, "!~");
        Assert.Equal("!~", draft.Headers[WopHeaders.SubMchId]);
    }

    // ==================== Execute 透传与旧重载 ====================

    [Fact]
    public void 子商户头_Execute实例重载_透传并入签()
    {
        var transport = new CapturingTransport();
        var client = WopClientTests.RsaBuilder().Build(transport);

        var result = client.Execute("POST", "/p", Encoding.UTF8.GetBytes("{}"),
            SecurityLevel.L0, "req-001", "PLF-SUB-001");

        Assert.False(result.Ok); // 空响应头 → 验签失败，但 Execute 不抛
        Assert.NotNull(transport.Draft);
        var draft = transport.Draft!;
        Assert.Equal("PLF-SUB-001", draft.Headers[WopHeaders.SubMchId]);
        Assert.Contains(WopHeaders.SubMchId, SignedNames(draft));
    }

    [Fact]
    public void 子商户头_Execute显式传输重载_透传并入签()
    {
        var transport = new CapturingTransport();
        var client = Client();

        var (result, response) = client.Execute(transport, "POST", "/p", Encoding.UTF8.GetBytes("{}"),
            SecurityLevel.L0, "req-001", "PLF-SUB-001");

        Assert.False(result.Ok);
        Assert.Equal(200, response.StatusCode);
        Assert.NotNull(transport.Draft);
        var draft = transport.Draft!;
        Assert.Equal("PLF-SUB-001", draft.Headers[WopHeaders.SubMchId]);
        Assert.Contains(WopHeaders.SubMchId, SignedNames(draft));
    }

    [Fact]
    public void 旧重载_requestId透传_子商户头缺席()
    {
        var bound = new CapturingTransport();
        WopClientTests.RsaBuilder().Build(bound).Execute("GET", "/p", null, SecurityLevel.L0, "req-001");
        var boundDraft = bound.Draft!;
        Assert.False(boundDraft.Headers.ContainsKey(WopHeaders.SubMchId));
        Assert.Equal("req-001", boundDraft.Headers[WopHeaders.RequestId]);

        var explicitTransport = new CapturingTransport();
        Client().Execute(explicitTransport, "GET", "/p", null, SecurityLevel.L0, "req-002");
        var explicitDraft = explicitTransport.Draft!;
        Assert.False(explicitDraft.Headers.ContainsKey(WopHeaders.SubMchId));
        Assert.Equal("req-002", explicitDraft.Headers[WopHeaders.RequestId]);
    }

    [Fact]
    public void Execute_新增重载_空transport_拒绝()
    {
        var client = Client();
        var noTransport = Assert.Throws<WopException>(() =>
            client.Execute("GET", "/p", null, SecurityLevel.L0, "req-001", "PLF-SUB-001"));
        Assert.Equal(WopErrorCode.Config, noTransport.ErrorCode);

        var nullTransport = Assert.Throws<WopException>(() =>
            client.Execute(null!, "GET", "/p", null, SecurityLevel.L0, "req-001", "PLF-SUB-001"));
        Assert.Equal(WopErrorCode.Config, nullTransport.ErrorCode);
    }

    sealed class CapturingTransport : IWopTransport
    {
        internal RequestDraft? Draft;

        public TransportResponse Send(RequestDraft draft)
        {
            Draft = draft;
            return new TransportResponse(200, new Dictionary<string, string>(), Array.Empty<byte>());
        }
    }
    // ==================== 入向不消费（附录 J/J3） ====================

    [Fact]
    public void 入向不消费子商户头_未入签额外携带仍通过()
    {
        var client = WopClientTests.RsaBuilder().Build();
        var headers = new Dictionary<string, string>
        {
            [WopHeaders.AppKey] = "platform",
            [WopHeaders.Timestamp] = "1724900000001",
            [WopHeaders.Nonce] = "resp-nonce",
        };
        var signedNames = headers.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        var canonical = CanonicalRequest.Build("v1/1800", "GET", "/q", "",
            CanonicalRequest.CanonicalHeaders(signedNames.ToDictionary(n => n, n => headers[n])));
        var sig = WopCrypto.Sign(client.Suite, WopClientTests.RespKeyMaterial(client.Suite),
            Encoding.UTF8.GetBytes(canonical), null);
        headers[WopHeaders.Sign] = SignHeader.Build(client.Suite.SecurityReq, 1800, signedNames, sig);
        headers[WopHeaders.SubMchId] = "PLF-SUB-001"; // 签名完成后追加：未入 signedHeaders

        var result = client.VerifyResponse("GET", "/q", headers, null);
        Assert.True(result.Ok);
    }

}
