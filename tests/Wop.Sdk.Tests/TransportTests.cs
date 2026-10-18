using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;
using Wop.Sdk;
using Xunit;

public class TransportTests
{
    static WopClient Client() => WopClientTests.RsaBuilder().Build();

    sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
        internal HttpRequestMessage? LastRequest;
        internal byte[]? LastBody;

        internal FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            System.Threading.CancellationToken cancellationToken)
        {
            LastRequest = request;
            LastBody = request.Content == null ? null : request.Content.ReadAsByteArrayAsync().Result;
            return Task.FromResult(_respond(request));
        }
    }

    [Fact]
    public void Send_自定义Handler无网络_请求头与体透传()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"ok\":true}", Encoding.UTF8, "application/json"),
        });
        var transport = new HttpClientTransport(handler, "https://gw.example.com");
        var client = Client();
        var draft = client.BuildRequest("POST", "/api/pay", Encoding.UTF8.GetBytes("{\"k\":1}"), SecurityLevel.L0);

        var resp = transport.Send(draft);

        Assert.Equal(200, resp.StatusCode);
        Assert.Equal("{\"ok\":true}", Encoding.UTF8.GetString(resp.Body));
        Assert.Equal("https://gw.example.com/api/pay", handler.LastRequest!.RequestUri!.ToString());
        Assert.Equal("demo-app", handler.LastRequest.Headers.GetValues("x-wop-appkey").First());
        Assert.Equal("application/json", handler.LastRequest.Content!.Headers.ContentType!.MediaType);
        Assert.Equal(draft.WireBody, handler.LastBody);
        Assert.True(resp.Headers.ContainsKey("Content-Type"));
    }

    [Fact]
    public void Send_无body_不带ContentType()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.NoContent));
        var transport = new HttpClientTransport(handler, "https://gw.example.com");
        var draft = Client().BuildRequest("GET", "/q", null, SecurityLevel.L0);
        transport.Send(draft);
        Assert.Null(handler.LastRequest!.Content);
    }

    [Fact]
    public void Send_响应头多值合并()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Array.Empty<byte>()) };
        response.Headers.Add("X-Multi", "a");
        response.Headers.Add("X-Multi", "b");
        var handler = new FakeHandler(_ => response);
        var transport = new HttpClientTransport(handler, "https://gw.example.com");
        var resp = transport.Send(Client().BuildRequest("GET", "/q", null, SecurityLevel.L0));
        Assert.Equal("a,b", resp.Headers["X-Multi"]);
    }

    [Fact]
    public void Send_非法基地址_配置类拒绝()
    {
        var transport = new HttpClientTransport(new FakeHandler(_ => new HttpResponseMessage()), "://bad");
        var draft = Client().BuildRequest("GET", "/q", null, SecurityLevel.L0);
        var ex = Assert.Throws<WopException>(() => transport.Send(draft));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
    }

    [Fact]
    public void Send_网络失败_配置类拒绝()
    {
        var handler = new FakeHandler(_ => throw new HttpRequestException("boom"));
        var transport = new HttpClientTransport(handler, "https://gw.example.com");
        var draft = Client().BuildRequest("GET", "/q", null, SecurityLevel.L0);
        var ex = Assert.Throws<WopException>(() => transport.Send(draft));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
    }

    [Fact]
    public void Send_响应体超上限_拒绝()
    {
        var big = new byte[HttpClientTransport.MaxResponseBytes + 1];
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(big),
        });
        var transport = new HttpClientTransport(handler, "https://gw.example.com");
        var draft = Client().BuildRequest("GET", "/q", null, SecurityLevel.L0);
        var ex = Assert.Throws<WopException>(() => transport.Send(draft));
        Assert.Equal(WopErrorCode.Protocol, ex.ErrorCode);
    }

    [Fact]
    public void Send_恰在上限_通过()
    {
        var exact = new byte[HttpClientTransport.MaxResponseBytes];
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(exact),
        });
        var transport = new HttpClientTransport(handler, "https://gw.example.com");
        var draft = Client().BuildRequest("GET", "/q", null, SecurityLevel.L0);
        var resp = transport.Send(draft);
        Assert.Equal(exact.Length, resp.Body.Length);
    }

    [Fact]
    public void Execute_一站式_构建发送校验()
    {
        // 平台响应闭环：FakeHandler 返回按 fixture 密钥构造的已签名响应
        var client = Client();
        var bodyText = "{\"code\":\"OK\"}";
        var headers = new Dictionary<string, string>();
        var responseHeaders = new Dictionary<string, string>();
        var wire = Encoding.UTF8.GetBytes(bodyText);
        responseHeaders[WopHeaders.AppKey] = "platform";
        responseHeaders[WopHeaders.Timestamp] = "1724900000001";
        responseHeaders[WopHeaders.Nonce] = "resp-nonce";
        responseHeaders[WopHeaders.ContentDigest] = ContentDigest.BuildHeaderValue(client.Suite, wire);
        var signedNames = responseHeaders.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        var canonical = CanonicalRequest.Build("v1/1800", "POST", "/api/pay", "",
            CanonicalRequest.CanonicalHeaders(signedNames.ToDictionary(n => n, n => responseHeaders[n])));
        var sig = WopCrypto.Sign(client.Suite,
            AsymmetricKeyMaterial.ParsePrivate(
                JsonDocument.Parse(File.OpenRead(Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json")))
                    .RootElement.GetProperty("keys").GetProperty("rsa3072").GetProperty("privatePkcs8B64").GetString()!,
                client.Suite),
            Encoding.UTF8.GetBytes(canonical), null);
        responseHeaders[WopHeaders.Sign] = SignHeader.Build(client.Suite.SecurityReq, 1800, signedNames, sig);

        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(wire),
        };
        foreach (var (name, value) in responseHeaders)
        {
            response.Headers.TryAddWithoutValidation(name, value);
        }
        var transport = new HttpClientTransport(new FakeHandler(_ => response), "https://gw.example.com");

        var (result, resp) = client.Execute(transport, "POST", "/api/pay", Encoding.UTF8.GetBytes("{\"k\":1}"), SecurityLevel.L0);
        Assert.True(result.Ok);
        Assert.Equal(bodyText, Encoding.UTF8.GetString(result.Plaintext!));
        Assert.Equal(200, resp.StatusCode);
    }

    [Fact]
    public void Execute_transport为空_拒绝()
    {
        var client = Client();
        Assert.Throws<WopException>(() => client.Execute(null!, "GET", "/q", null, SecurityLevel.L0));
    }
}
