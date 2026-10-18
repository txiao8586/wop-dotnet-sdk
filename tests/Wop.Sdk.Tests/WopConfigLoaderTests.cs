using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Wop.Sdk;
using Xunit;

// 配置加载链共享进程级全局态（cwd/env/缓存），相关类须串行执行
[CollectionDefinition("config-global", DisableParallelization = true)]
public class ConfigGlobalCollection { }

[Collection("config-global")]
public class WopConfigLoaderTests
{
    static readonly JsonElement Keys = JsonDocument.Parse(File.OpenRead(
        Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json"))).RootElement.GetProperty("keys");

    static string K(string name, string field) => Keys.GetProperty(name).GetProperty(field).GetString()!;

    static string WriteTempConfig(string json)
    {
        var path = Path.Combine(Path.GetTempPath(), "wop-config-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, json, Encoding.UTF8);
        return path;
    }

    static string ValidConfigJson(string? serverRoot = null)
    {
        // 普通拼接而非 raw string：JSON 花括号与 raw 定界符交错会被截断（P0 遗留语法破损）
        return "{\n" +
            "  \"appKey\": \"demo-app\",\n" +
            "  \"suite\": \"WOP-RSA3072-SHA256\",\n" +
            "  \"merchantPrivateKey\": " + JsonSerializer.Serialize(K("rsa3072", "privatePkcs8B64")) + ",\n" +
            "  \"platformPublicKey\": " + JsonSerializer.Serialize(K("rsa3072", "publicSpkiB64")) + ",\n" +
            "  \"serverRoot\": " + JsonSerializer.Serialize(serverRoot ?? "https://gw.example.com/gateway") + ",\n" +
            "  \"expiredSeconds\": 1800\n" +
            "}";
    }

    [Fact]
    public void Load_合法配置_解析成功()
    {
        WopConfigLoader.ClearCache();
        var path = WriteTempConfig(ValidConfigJson());
        var config = WopConfigLoader.Load(path);
        Assert.Equal("demo-app", config.AppKey);
        Assert.Equal("WOP-RSA3072-SHA256", config.Suite);
        Assert.Equal("https://gw.example.com/gateway", config.ServerRoot);
        Assert.Equal(1800, config.ExpiredSeconds);
        Assert.Equal(10_000, config.HttpClient.ConnectTimeout);
    }

    [Fact]
    public void Load_重复appKey_拒绝()
    {
        var json = """
            {
              "appKey": "a",
              "appKey": "b",
              "suite": "WOP-RSA3072-SHA256",
              "merchantPrivateKey": "x",
              "platformPublicKey": "y",
              "serverRoot": "https://gw.example.com/gateway"
            }
            """;
        var ex = Assert.Throws<WopException>(() => WopConfigLoader.Load(WriteTempConfig(json)));
        Assert.Equal(WopErrorCode.Config, ex.ErrorCode);
        Assert.Contains("appKey 重复", ex.Message);
    }

    [Fact]
    public void Load_重复serverRoot_拒绝()
    {
        var json = """
            {
              "appKey": "demo-app",
              "suite": "WOP-RSA3072-SHA256",
              "merchantPrivateKey": "x",
              "platformPublicKey": "y",
              "serverRoot": "https://gw.example.com/gateway",
              "serverRoot": "https://dup.example.com/gateway"
            }
            """;
        var ex = Assert.Throws<WopException>(() => WopConfigLoader.Load(WriteTempConfig(json)));
        Assert.Contains("serverRoot 重复", ex.Message);
    }

    [Fact]
    public void Load_缺少appKey_拒绝()
    {
        var json = ValidConfigJson().Replace("\"appKey\": \"demo-app\",\n", "");
        var ex = Assert.Throws<WopException>(() => WopConfigLoader.Load(WriteTempConfig(json)));
        Assert.Contains("缺少必填项: appKey", ex.Message);
    }

    [Fact]
    public void Load_serverRoot非HTTPS_拒绝()
    {
        var ex = Assert.Throws<WopException>(() =>
            WopConfigLoader.Load(WriteTempConfig(ValidConfigJson("http://gw.example.com/gateway"))));
        Assert.Contains("须为 HTTPS", ex.Message);
    }

    [Fact]
    public void Load_serverRoot含query_拒绝()
    {
        var ex = Assert.Throws<WopException>(() =>
            WopConfigLoader.Load(WriteTempConfig(ValidConfigJson("https://gw.example.com/gateway?x=1"))));
        Assert.Contains("不得含 query", ex.Message);
    }

    [Fact]
    public void Load_backup含fragment_逐项拒绝()
    {
        var json = ValidConfigJson().Replace(
            "\"expiredSeconds\": 1800",
            "\"backupServerRoots\": [\"https://b.example.com/gateway#frag\"],\n  \"expiredSeconds\": 1800");
        var ex = Assert.Throws<WopException>(() => WopConfigLoader.Load(WriteTempConfig(json)));
        Assert.Contains("backupServerRoots[0]", ex.Message);
    }

    [Fact]
    public void Load_expiredSeconds非正_拒绝()
    {
        var json = ValidConfigJson().Replace("\"expiredSeconds\": 1800", "\"expiredSeconds\": 0");
        var ex = Assert.Throws<WopException>(() => WopConfigLoader.Load(WriteTempConfig(json)));
        Assert.Contains("expiredSeconds 须为正整数", ex.Message);
    }

    [Fact]
    public void Load_BOM_剥离后成功()
    {
        var path = WriteTempConfig("\uFEFF" + ValidConfigJson());
        var config = WopConfigLoader.Load(path);
        Assert.Equal("demo-app", config.AppKey);
    }

    [Fact]
    public void Load_空文件_拒绝()
    {
        var ex = Assert.Throws<WopException>(() => WopConfigLoader.Load(WriteTempConfig("   ")));
        Assert.Contains("空文件", ex.Message);
    }

    [Fact]
    public void Load_同路径缓存复用()
    {
        WopConfigLoader.ClearCache();
        var path = WriteTempConfig(ValidConfigJson());
        var a = WopConfigLoader.Load(path);
        var b = WopConfigLoader.Load(path);
        Assert.Same(a, b);
    }

    [Fact]
    public void ClearCache_后重新解析()
    {
        WopConfigLoader.ClearCache();
        var path = WriteTempConfig(ValidConfigJson());
        var a = WopConfigLoader.Load(path);
        WopConfigLoader.ClearCache();
        var b = WopConfigLoader.Load(path);
        Assert.NotSame(a, b);
    }

    [Fact]
    public void WopSdkConfig_ToString_私钥打码()
    {
        var config = WopConfigLoader.Load(WriteTempConfig(ValidConfigJson()));
        var text = config.ToString();
        Assert.Contains("****", text);
        Assert.DoesNotContain(K("rsa3072", "privatePkcs8B64"), text);
    }

    [Fact]
    public void FromConfig_创建可Execute客户端()
    {
        WopConfigLoader.ClearCache();
        var config = WopConfigLoader.Load(WriteTempConfig(ValidConfigJson()));
        var client = WopClient.FromConfig(config);
        Assert.NotNull(client);
    }

    [Fact]
    public void Builder无Transport_Execute拒绝()
    {
        var client = WopClientTests.RsaBuilder().Build();
        var ex = Assert.Throws<WopException>(() =>
            client.Execute("GET", "/q", null, SecurityLevel.L0));
        Assert.Contains("未配置传输层", ex.Message);
    }

    sealed class FakeHandler : System.Net.Http.HttpMessageHandler
    {
        private readonly Func<System.Net.Http.HttpRequestMessage, System.Net.Http.HttpResponseMessage> _respond;
        internal FakeHandler(Func<System.Net.Http.HttpRequestMessage, System.Net.Http.HttpResponseMessage> respond) =>
            _respond = respond;
        protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(
            System.Net.Http.HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(_respond(request));
    }

    [Fact]
    public void Execute_非2xx_抛GatewayResponseException()
    {
        var handler = new FakeHandler(_ =>
            new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.BadRequest)
            {
                Content = new System.Net.Http.StringContent("err"),
            });
        var config = WopSdkConfig.Builder()
            .AppKey("demo-app")
            .Suite("WOP-RSA3072-SHA256")
            .MerchantPrivateKey(K("rsa3072", "privatePkcs8B64"))
            .PlatformPublicKey(K("rsa3072", "publicSpkiB64"))
            .ServerRoot("https://gw.example.com/gateway")
            .Transport(new HttpClientTransport(handler, "https://gw.example.com/gateway"))
            .Build();
        var client = WopClient.FromConfig(config);
        var ex = Assert.Throws<WopGatewayResponseException>(() =>
            client.Execute("GET", "/q", null, SecurityLevel.L0));
        Assert.Equal(400, ex.StatusCode);
        Assert.Contains("400", ex.Message);
        Assert.Equal("err", Encoding.UTF8.GetString(ex.Body));
    }

    [Fact]
    public void ValidateApiPath_拒绝双斜杠()
    {
        var ex = Assert.Throws<WopException>(() =>
            WopClientTests.RsaBuilder().Build().BuildRequest("GET", "//evil/path", null, SecurityLevel.L0));
        Assert.Contains("// 开头", ex.Message);
    }

    [Fact]
    public void JoinUrl_保留contextPath()
    {
        var url = ConfigValidator.JoinUrl("https://gw.example.com/gateway", "/gateway/order/create");
        Assert.Equal("https://gw.example.com/gateway/gateway/order/create", url);
    }

    [Fact]
    public void ResetDefault_clearCache后加载新配置()
    {
        WopConfigLoader.ClearCache();
        WopClient.ResetDefault();
        var path1 = WriteTempConfig(ValidConfigJson());
        Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, path1);
        try
        {
            var c1 = WopClient.DefaultClient();
            WopConfigLoader.ClearCache();
            WopClient.ResetDefault();
            var path2 = WriteTempConfig(ValidConfigJson("https://gw2.example.com/gateway"));
            Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, path2);
            var c2 = WopClient.DefaultClient();
            Assert.NotSame(c1, c2);
        }
        finally
        {
            Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, null);
            WopConfigLoader.ClearCache();
            WopClient.ResetDefault();
        }
    }

    [Fact]
    public void DefaultClient_并发首调单实例()
    {
        WopConfigLoader.ClearCache();
        WopClient.ResetDefault();
        var path = WriteTempConfig(ValidConfigJson());
        Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, path);
        try
        {
            WopClient? a = null;
            WopClient? b = null;
            Parallel.Invoke(
                () => a = WopClient.DefaultClient(),
                () => b = WopClient.DefaultClient());
            Assert.Same(a, b);
        }
        finally
        {
            Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, null);
            WopConfigLoader.ClearCache();
            WopClient.ResetDefault();
        }
    }

    [Fact]
    public void Load_成员间缺逗号_解析失败拒绝()
    {
        var json = "{\"appKey\": \"a\" \"suite\": \"WOP-RSA3072-SHA256\"}";
        var path = WriteTempConfig(json);
        var ex = Assert.Throws<WopException>(() => WopConfigLoader.Load(path));
        Assert.Contains("配置文件 JSON 解析失败", ex.Message);
    }

    [Fact]
    public void Load_根对象后尾随内容_解析失败拒绝()
    {
        var path = WriteTempConfig(ValidConfigJson() + "garbage");
        var ex = Assert.Throws<WopException>(() => WopConfigLoader.Load(path));
        Assert.Contains("配置文件 JSON 解析失败", ex.Message);
    }
}
