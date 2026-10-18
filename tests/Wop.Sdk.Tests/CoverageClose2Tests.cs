using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Wop.Sdk;
using Xunit;


public class CoverageClose3Tests
{
    [Theory]
    [InlineData("{\"a\":\"x\\")]          // 转义后截断
    [InlineData("{\"a\":123}")]           // 数值后对象结束（SkipValue 外层边界）
    public void Envelope_截断与数值边界_拒绝(string body)
    {
        Assert.Throws<WopException>(() => EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }

    [Fact]
    public void Transport_超长流触发LimitStream断流_拒绝()
    {
        var content = new EndlessContent();
        var response = new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = content };
        var transport = new HttpClientTransport(new RelayHandler(response), "https://gw.example.com");
        var draft = WopClientTests.RsaBuilder().Build().BuildRequest("GET", "/q", null, SecurityLevel.L0);
        var ex = Assert.Throws<WopException>(() => transport.Send(draft));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
    }

    sealed class RelayHandler : System.Net.Http.HttpMessageHandler
    {
        private readonly System.Net.Http.HttpResponseMessage _response;
        internal RelayHandler(System.Net.Http.HttpResponseMessage response) => _response = response;
        protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(
            System.Net.Http.HttpRequestMessage request, System.Threading.CancellationToken ct)
            => Task.FromResult(_response);
    }

    /// <summary>读不完的流（模拟 chunked 无限响应）：限额生效于读取过程中（D5）。</summary>
    sealed class EndlessContent : System.Net.Http.HttpContent
    {
        protected override Task<Stream> CreateContentReadStreamAsync()
            => Task.FromResult<Stream>(new EndlessStream());

        protected override Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context)
            => throw new InvalidOperationException();

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    sealed class EndlessStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            Array.Clear(buffer, offset, count);
            return count;
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) { }
        public override void Write(byte[] buffer, int offset, int count) { }
    }
}

public class TrailingBitAndSkipStringTests
{
    // ① 与 Go RawURLEncoding.Strict() 对齐：非规范尾随位拒绝
    [Theory]
    [InlineData("abd")]   // d=29，低 4 位非零（%4==3）
    [InlineData("AB")]    // B=1，低 2 位非零（%4==2）
    [InlineData("ab-")]   // '-'=62，低 2 位非零
    public void DecodeB64Url_非规范尾随位_拒绝(string s)
    {
        var ex = Assert.Throws<WopException>(() => Codec.DecodeB64Url(s));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
    }

    [Theory]
    [InlineData("AA", 1)]     // A=0 尾随位全零 → 1 字节 0x00
    [InlineData("AAA", 2)]    // 2 字节 0x00
    [InlineData("AAg", 2)]    // g=32，低 4 位零 → 合法
    [InlineData("gAA", 2)]
    public void DecodeB64Url_规范尾随位_接受(string s, int len)
    {
        Assert.Equal(len, Codec.DecodeB64Url(s).Length);
    }

    // ② SkipValue 字符串感知：串内结构字符不参与深度/边界判定（容忍未知字段）
    [Theory]
    [InlineData("{\"a\":{\"b\":\"},\"},\"encrypted\":\"AA\"}")]   // 串内 '}' 
    [InlineData("{\"a\":{\"b\":\"{x,[y\"},\"encrypted\":\"AA\"}")] // 串内 '{' '['
    [InlineData("{\"a\":[\"x,y\"],\"encrypted\":\"AA\"}")]         // 串内 ','
    [InlineData("{\"a\":\"}\",\"encrypted\":\"AA\"}")]
    public void Envelope_未知字段内结构字符_不误判(string body)
    {
        Assert.Equal("AA", EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }
}

public class UnicodeEscapeTests
{
    [Fact]
    public void Envelope_uXXXX转义_未知字段容忍()
    {
        // .NET System.Text.Json 默认将非 ASCII 序列化为 \uXXXX —— 平台侧可能如此发响应
        var body = "{\"msg\":\"\\u4e2d\\u6587\",\"encrypted\":\"AA\"}";
        Assert.Equal("AA", EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }

    [Fact]
    public void Envelope_代理对转义_容忍()
    {
        var body = "{\"e\":\"\\ud83d\\ude00\",\"encrypted\":\"AA\"}";   // 😀 = U+1F600
        Assert.Equal("AA", EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }

    [Theory]
    [InlineData("{\"a\":\"\\uZZZZ\",\"encrypted\":\"AA\"}")]   // 非 hex
    [InlineData("{\"a\":\"\\u00\"}")]                          // 截断
    [InlineData("{\"a\":\"\\u004\"}")]                         // 截断
    public void Envelope_非法u转义_拒绝(string body)
    {
        Assert.Throws<WopException>(() => EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }

    [Fact]
    public void Envelope_u转义的encrypted键名_语义等价_RFC8259()
    {
        // RFC 8259：\u 转义在键名中与其解码字符完全等价 → "\u0065ncrypted" 即 "encrypted"
        var body = "{\"\\u0065ncrypted\":\"AA\"}";
        Assert.Equal("AA", EncryptedEnvelope.Extract(Encoding.UTF8.GetBytes(body)));
    }
}

/// <summary>WopClient 实例链路与 WopCrypto 密钥缺失分支闭合（CI 门禁 ≥98% 行+分支）。</summary>
public class CoverageClose5Tests
{
    static string Vec(string dotted)
    {
        using var doc = System.Text.Json.JsonDocument.Parse(File.OpenRead(
            Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json")));
        var node = doc.RootElement;
        foreach (var part in dotted.Split('.')) node = node.GetProperty(part);
        return node.GetString()!;
    }

    [Fact]
    public void FromConfig_null配置_拒绝()
    {
        var ex = Assert.Throws<WopException>(() => WopClient.FromConfig(null!));
        Assert.Contains("config 为空", ex.Message);
    }

    [Fact]
    public void Execute_path为null按空串拒绝_且非2xx走网关异常()
    {
        var transport = new CannedTransport();
        var client = new WopClientBuilder()
            .AppKey("demo-app")
            .Suite("WOP-RSA3072-SHA256")
            .MerchantPrivateKey(Vec("keys.rsa3072.privatePkcs8B64"))
            .PlatformPublicKey(Vec("keys.rsa3072.publicSpkiB64"))
            .GatewayBaseUrl("https://gw.example.com/gateway")
            .Build(transport);

        // path ?? "" 分支：null 归一为空串后 fail-fast
        Assert.Throws<WopException>(() => client.Execute("GET", null!, null, SecurityLevel.L0));

        // 实例 transport 发送链 + EnsureSuccessStatus 非 2xx 拦截
        var ex = Assert.Throws<WopGatewayResponseException>(() => client.Execute("GET", "/x", null, SecurityLevel.L0));
        Assert.Equal(502, ex.StatusCode);

        // 2xx 回路：进 Verify 并以 VerifyResult（失败）落回 return 语句
        transport.Status = 200;
        var result = client.Execute("GET", "/x", null, SecurityLevel.L0);
        Assert.NotNull(result);

        // <200：第一条比较即短路（&& 短路弧）
        transport.Status = 150;
        Assert.Throws<WopGatewayResponseException>(() => client.Execute("GET", "/x", null, SecurityLevel.L0));
    }

    [Fact]
    public void Crypto_SM2密钥缺失或userId空_拒绝()
    {
        var suite = AlgorithmSuite.Parse("WOP-SM2-SM3");
        var uid = Encoding.UTF8.GetBytes("1234567812345678");
        var msg = Encoding.UTF8.GetBytes("m");

        var noKey = Assert.Throws<WopException>(() => WopCrypto.Sign(suite, new AsymmetricKeyMaterial(), msg, uid));
        Assert.Contains("SM2 套件缺少私钥", noKey.Message);

        var priv = AsymmetricKeyMaterial.ParsePrivate(Vec("keys.sm2.privateDB64"), suite);
        Assert.Throws<WopException>(() => WopCrypto.Sign(suite, priv, msg, null));
        Assert.Throws<WopException>(() => WopCrypto.Sign(suite, priv, msg, Array.Empty<byte>()));

        var sig = Codec.EncodeB64Url(new byte[64]); // 定长 64 通过前置校验即可触及密钥检查
        var noPub = Assert.Throws<WopException>(() => WopCrypto.Verify(suite, new AsymmetricKeyMaterial(), msg, sig, uid));
        Assert.Contains("SM2 套件缺少验签公钥", noPub.Message);

        var pub = AsymmetricKeyMaterial.ParsePublic(Vec("keys.sm2.publicPointB64"), suite);
        Assert.Throws<WopException>(() => WopCrypto.Verify(suite, pub, msg, sig, null));
    }

    sealed class CannedTransport : IWopTransport
    {
        public int Status = 502;

        public TransportResponse Send(RequestDraft draft) =>
            new(Status, new Dictionary<string, string>(), Encoding.UTF8.GetBytes("err"));
    }
}
