using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Reqnroll;
using Wop.Sdk;
using Xunit;

// Gherkin 场景步骤绑定（MerchantJourney.feature）。 条款 tag 见 feature 文件 @tag（F1-F9/D1/D2/I1-I7/Q1）。 // spec:Gherkin
// D5 纪律：平台侧响应在本步骤类内独立构造（fixture 平台私钥签名），不复用被测 SDK 的出向代码。
[Binding]
public sealed class MerchantJourneySteps
{
    static readonly JsonElement Keys = JsonDocument.Parse(File.OpenRead(
        Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json"))).RootElement.GetProperty("keys");

    static string K(string name, string field) => Keys.GetProperty(name).GetProperty(field).GetString()!;

    static readonly byte[] Body = Encoding.UTF8.GetBytes("{\"k\":1}");

    // 场景上下文（SpecFlow per-scenario 实例化，场景间隔离）
    private WopClient? _client;
    private RequestDraft? _draft1;
    private RequestDraft? _draft2;
    private WopException? _buildError;
    private VerifyResult? _result;
    private Dictionary<string, string> _respHeaders = new();
    private byte[] _respBody = Array.Empty<byte>();
    private string _respMethod = "POST";
    private string _respPath = "/api/pay";

    // ==================== Given ====================

    [Given(@"fixture 密钥已就绪")]
    public void GivenFixtureKeys()
    {
        Assert.False(string.IsNullOrEmpty(K("rsa3072", "privatePkcs8B64")));
        Assert.False(string.IsNullOrEmpty(K("sm2", "privateDB64")));
    }

    [Given(@"RSA 客户端已构建")]
    public void GivenRsaClient()
    {
        _client = RsaFixedClient();
    }

    [Given(@"RSA 客户端已用默认随机源构建")]
    public void GivenRsaClientDefaultRandom()
    {
        _client = WopClient.Builder()
            .AppKey("demo-app").Suite("WOP-RSA3072-SHA256")
            .MerchantPrivateKey(K("rsa3072", "privatePkcs8B64"))
            .PlatformPublicKey(K("rsa3072", "publicSpkiB64"))
            .WithClock(() => 1724900000000)
            .Build();
    }

    [Given(@"平台已按 ""(.+)"" ""(.+)"" 签发 L0 响应")]
    public void GivenPlatformL0Response(string method, string path)
    {
        (_respHeaders, _respBody) = BuildSignedResponse(method, path, Body);
        _respMethod = method;
        _respPath = path;
    }

    [Given(@"平台已按 ""(.+)"" ""(.+)"" 签发 L2 加密响应")]
    public void GivenPlatformL2Response(string method, string path)
    {
        (_respHeaders, _respBody) = BuildEncryptedResponse(method, path, Body);
        _respMethod = method;
        _respPath = path;
    }

    [Given(@"平台已按 ""(.+)"" ""(.+)"" 签发跨族 digest 响应")]
    public void GivenPlatformCrossFamilyDigestResponse(string method, string path)
    {
        (_respHeaders, _respBody) = BuildSignedResponse(method, path, Body, crossFamilyDigest: true);
        _respMethod = method;
        _respPath = path;
    }

    [Given(@"攻击者篡改了响应签名")]
    public void GivenTamperSignature()
    {
        var sign = _respHeaders[WopHeaders.Sign];
        var sig = sign.Split(' ')[1].Split('/')[3];
        _respHeaders[WopHeaders.Sign] = sign.Substring(0, sign.Length - sig.Length) +
                                        FlipB64UrlChar(sig[0]) + sig.Substring(1);
    }

    [Given(@"攻击者移除了 digest 头")]
    public void GivenRemoveDigest()
    {
        _respHeaders.Remove(WopHeaders.ContentDigest);
    }

    [Given(@"攻击者在签名段追加了填充字符")]
    public void GivenAppendPadding()
    {
        _respHeaders[WopHeaders.Sign] += "==";   // spec D1：拒收 '='
    }

    // ==================== When ====================

    [When(@"商户以套件 ""(.+)"" 配置 RSA 密钥并构建客户端")]
    public void WhenBuildRsaClient(string suiteReq)
    {
        try
        {
            _client = WopClient.Builder()
                .AppKey("demo-app").Suite(suiteReq)
                .MerchantPrivateKey(K("rsa3072", "privatePkcs8B64"))
                .PlatformPublicKey(K("rsa3072", "publicSpkiB64"))
                .Build();
        }
        catch (WopException e)
        {
            _buildError = e;
        }
    }

    [When(@"商户以套件 ""(.+)"" 配置 SM2 密钥并构建客户端")]
    public void WhenBuildSm2Client(string suiteReq)
    {
        try
        {
            _client = WopClient.Builder()
                .AppKey("demo-app").Suite(suiteReq)
                .MerchantPrivateKey(K("sm2", "privateDB64"))
                .PlatformPublicKey(K("sm2", "publicPointB64"))
                .Build();
        }
        catch (WopException e)
        {
            _buildError = e;
        }
    }

    [When(@"商户尝试以套件 ""(.+)"" 构建客户端")]
    public void WhenBuildBadSuite(string suiteReq)
    {
        try
        {
            _client = WopClient.Builder()
                .AppKey("demo-app").Suite(suiteReq)
                .MerchantPrivateKey(K("rsa3072", "privatePkcs8B64"))
                .PlatformPublicKey(K("rsa3072", "publicSpkiB64"))
                .Build();
        }
        catch (WopException e)
        {
            _buildError = e;
        }
    }

    [When(@"商户以空 appKey 构建客户端")]
    public void WhenBuildEmptyAppKey()
    {
        try
        {
            _client = WopClient.Builder()
                .AppKey("").Suite("WOP-RSA3072-SHA256")
                .MerchantPrivateKey(K("rsa3072", "privatePkcs8B64"))
                .PlatformPublicKey(K("rsa3072", "publicSpkiB64"))
                .Build();
        }
        catch (WopException e)
        {
            _buildError = e;
        }
    }

    [When(@"商户构建 L0 请求 ""(.+)"" ""(.+)"" 带 body")]
    public void WhenBuildL0(string method, string path)
    {
        _draft1 = Client().BuildRequest(method, path, Body, SecurityLevel.L0);
    }

    [When(@"商户构建 L0 请求 ""(.+)"" ""(.+)"" 无 body")]
    public void WhenBuildL0NoBody(string method, string path)
    {
        _draft1 = Client().BuildRequest(method, path, null, SecurityLevel.L0);
    }

    [When(@"商户两次构建相同 L0 请求 ""(.+)"" ""(.+)"" 带 body")]
    public void WhenBuildL0Twice(string method, string path)
    {
        // 附录 I/I3：缺省 requestId 属 CSPRNG 豁免项，注入固定生成器后全头可重放
        var prev = RequestId.Generator;
        RequestId.Generator = () => "fixedreq000000000000000000000001";
        try
        {
            var c = Client();
            _draft1 = c.BuildRequest(method, path, Body, SecurityLevel.L0);
            _draft2 = c.BuildRequest(method, path, Body, SecurityLevel.L0);
        }
        finally
        {
            RequestId.Generator = prev;
        }
    }

    [When(@"商户构建 L2 请求 ""(.+)"" ""(.+)"" 带 body")]
    public void WhenBuildL2(string method, string path)
    {
        _draft1 = Client().BuildRequest(method, path, Body, SecurityLevel.L2);
    }

    [When(@"商户校验该响应")]
    public void WhenVerifyResponse()
    {
        _result = Client().VerifyResponse(_respMethod, _respPath, _respHeaders, _respBody);
    }

    [When(@"商户校验回调 ""(.+)""")]
    public void WhenVerifyCallback(string callbackUrl)
    {
        _result = Client().VerifyCallback(callbackUrl, _respHeaders, _respBody);
    }

    [When(@"商户通过可插拔 transport 一站式调用 ""(.+)"" ""(.+)"" 带 body")]
    public void WhenExecute(string method, string path)
    {
        var transport = new RelayTransport(new TransportResponse(200, _respHeaders, _respBody));
        var (result, _) = Client().Execute(transport, method, path, Body, SecurityLevel.L0);
        _result = result;
    }

    // ==================== Then ====================

    [Then(@"客户端套件为 ""(.+)""")]
    public void ThenSuiteIs(string suiteReq)
    {
        Assert.Null(_buildError);
        Assert.Equal(suiteReq, Client().Suite.SecurityReq);
    }

    [Then(@"构建失败且错误码为 ""(.+)""")]
    public void ThenBuildFailed(string code)
    {
        Assert.NotNull(_buildError);
        Assert.Equal(code, _buildError!.ErrorCode.ToString());
    }

    [Then(@"请求头含合法 x-wop-sign")]
    public void ThenSignHeaderValid()
    {
        var parsed = SignHeader.Parse(_draft1!.Headers[WopHeaders.Sign]);
        Assert.Equal("v1", parsed.ProtocolVersion);
        Assert.True(parsed.SignedHeaders.Count > 0);
    }

    [Then(@"x-wop-content-digest 已列入签名头")]
    public void ThenDigestSigned()
    {
        var parsed = SignHeader.Parse(_draft1!.Headers[WopHeaders.Sign]);
        Assert.Contains(WopHeaders.ContentDigest, parsed.SignedHeaders);   // I1
    }

    [Then(@"wireBody 为原文")]
    public void ThenWireBodyIsPlaintext()
    {
        Assert.True(_draft1!.WireBody!.SequenceEqual(Body));
    }

    [Then(@"请求头不含 x-wop-content-digest")]
    public void ThenDigestAbsent()
    {
        Assert.False(_draft1!.Headers.ContainsKey(WopHeaders.ContentDigest));   // D2
    }

    [Then(@"两次请求头与 wireBody 完全一致")]
    public void ThenIdempotent()
    {
        Assert.Equal(_draft1!.Method, _draft2!.Method);
        Assert.Equal(_draft1.Path, _draft2.Path);
        Assert.Equal(_draft1.WireBody, _draft2.WireBody);
        Assert.Equal(_draft1.Headers, _draft2.Headers);
    }

    [Then(@"两次 nonce 不同")]
    public void ThenNonceDiffers()
    {
        Assert.NotEqual(
            _draft1!.Headers[WopHeaders.Nonce],
            _draft2!.Headers[WopHeaders.Nonce]);
    }

    [Then(@"wireBody 为 JSON 信封")]
    public void ThenWireBodyIsEnvelope()
    {
        var s = Encoding.UTF8.GetString(_draft1!.WireBody!);
        Assert.StartsWith("{\"encrypted\":\"", s);
        Assert.EndsWith("\"}", s);
        EncryptedEnvelope.Extract(_draft1.WireBody!);   // 可解析且合法
    }

    [Then(@"请求头含 x-wop-encrypt 指令头")]
    public void ThenEncryptHeaderPresent()
    {
        var (level, _) = EncryptHeader.Parse(_draft1!.Headers[WopHeaders.Encrypt]);
        Assert.Equal("L2", level);
    }

    [Then(@"x-wop-content-digest 基于信封字节而非原文")]
    public void ThenDigestOverEnvelope()
    {
        var digest = _draft1!.Headers[WopHeaders.ContentDigest];
        Assert.Equal(digest, ContentDigest.BuildHeaderValue(Client().Suite, _draft1.WireBody!));
        Assert.NotEqual(digest, ContentDigest.BuildHeaderValue(Client().Suite, Body));
    }

    [Then(@"校验通过且明文与响应体一致")]
    public void ThenVerifyOkL0()
    {
        Assert.True(_result!.Ok);
        Assert.Equal(_respBody, _result.Plaintext);
    }

    [Then(@"校验通过且解密明文为原文")]
    public void ThenVerifyOkL2()
    {
        Assert.True(_result!.Ok);
        Assert.Equal(Encoding.UTF8.GetString(Body), Encoding.UTF8.GetString(_result.Plaintext!));
    }

    [Then(@"校验失败且错误码为 ""(.+)""")]
    public void ThenVerifyFailed(string code)
    {
        Assert.False(_result!.Ok);
        Assert.Equal(code, _result.ErrorCode!.ToString());
    }

    [Then(@"失败原因为固定模糊文案")]
    public void ThenFuzzyReason()
    {
        Assert.Equal("签名验证失败", _result!.Reason);   // I7
    }

    [Then(@"校验通过")]
    public void ThenVerifyOk()
    {
        Assert.True(_result!.Ok);
    }

    [Then(@"调用结果校验通过")]
    public void ThenExecuteOk()
    {
        Assert.True(_result!.Ok);
    }

    // ==================== 平台侧响应构造（D5：独立于 SDK 出向代码） ====================

    static WopClient RsaFixedClient() => WopClient.Builder()
        .AppKey("demo-app").Suite("WOP-RSA3072-SHA256")
        .MerchantPrivateKey(K("rsa3072", "privatePkcs8B64"))
        .PlatformPublicKey(K("rsa3072", "publicSpkiB64"))
        .WithClock(() => 1724900000000)
        .WithNonce(() => "nonce-001")
        .Build();

    private WopClient Client()
    {
        Assert.NotNull(_client);
        return _client!;
    }

    static AsymmetricKeyMaterial PlatformKey() =>
        AsymmetricKeyMaterial.ParsePrivate(K("rsa3072", "privatePkcs8B64"),
            AlgorithmSuite.Parse("WOP-RSA3072-SHA256"));

    static (Dictionary<string, string> headers, byte[] wireBody) BuildSignedResponse(
        string method, string path, byte[] body, bool crossFamilyDigest = false)
    {
        var headers = new Dictionary<string, string>
        {
            [WopHeaders.AppKey] = "platform",
            [WopHeaders.Timestamp] = "1724900000001",
            [WopHeaders.Nonce] = "resp-nonce",
        };
        // 跨族构造：RSA 客户端 + sm3 标签（签名对头仍有效 → 族耦合校验（I5）负责拒绝）
        headers[WopHeaders.ContentDigest] = crossFamilyDigest
            ? "sm3 " + Codec.LowerHex(ContentDigest.Compute(
                  AlgorithmSuite.Parse("WOP-SM2-SM3"), body))
            : ContentDigest.BuildHeaderValue(AlgorithmSuite.Parse("WOP-RSA3072-SHA256"), body);
        return FinishSignedResponse(headers, method, path, body);
    }

    static (Dictionary<string, string> headers, byte[] wireBody) BuildEncryptedResponse(
        string method, string path, byte[] body)
    {
        var suite = AlgorithmSuite.Parse("WOP-RSA3072-SHA256");
        var cek = new byte[suite.CekLength];
        var iv = new byte[12];
        var sealedBytes = WopCrypto.SealMessage(suite, body, cek, iv);
        var wireBody = EncryptedEnvelope.Wrap(Codec.EncodeB64Url(sealedBytes));
        var wrapped = WopCrypto.WrapDek(suite, PlatformKeyPublic(),
            Encoding.UTF8.GetBytes(DekPayload.Encode(suite.MessageAlgorithm, cek, iv)));
        var headers = new Dictionary<string, string>
        {
            [WopHeaders.AppKey] = "platform",
            [WopHeaders.Timestamp] = "1724900000001",
            [WopHeaders.Nonce] = "resp-nonce",
            [WopHeaders.Encrypt] = EncryptHeader.BuildL2(wrapped),
            [WopHeaders.ContentDigest] = ContentDigest.BuildHeaderValue(suite, wireBody),
        };
        return FinishSignedResponse(headers, method, path, wireBody);
    }

    static AsymmetricKeyMaterial PlatformKeyPublic() =>
        AsymmetricKeyMaterial.ParsePublic(K("rsa3072", "publicSpkiB64"),
            AlgorithmSuite.Parse("WOP-RSA3072-SHA256"));

    static (Dictionary<string, string>, byte[]) FinishSignedResponse(
        Dictionary<string, string> headers, string method, string path, byte[] wireBody)
    {
        var suite = AlgorithmSuite.Parse("WOP-RSA3072-SHA256");
        var signedNames = headers.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        var signedMap = signedNames.ToDictionary(n => n, n => headers[n], StringComparer.Ordinal);
        var canonical = CanonicalRequest.Build("v1/1800", method, path, "",
            CanonicalRequest.CanonicalHeaders(signedMap));
        var sig = WopCrypto.Sign(suite, PlatformKey(), Encoding.UTF8.GetBytes(canonical), null);
        headers[WopHeaders.Sign] = SignHeader.Build(suite.SecurityReq, 1800, signedNames, sig);
        return (headers, wireBody);
    }

    static char FlipB64UrlChar(char c)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        var idx = alphabet.IndexOf(c);
        return alphabet[(idx + 7) % alphabet.Length];
    }

    /// <summary>可插拔传输 mock（Q1：transport 可替换，商户可自带栈）。</summary>
    sealed class RelayTransport : IWopTransport
    {
        private readonly TransportResponse _response;
        internal RelayTransport(TransportResponse response) => _response = response;
        public TransportResponse Send(RequestDraft draft) => _response;
    }
}
