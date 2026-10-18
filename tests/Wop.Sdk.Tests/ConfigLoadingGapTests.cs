using System;
using System.IO;
using System.Text.Json;
using Wop.Sdk;
using Xunit;

// 配置加载链覆盖闭合：parser 预扫/反序列化负例、validator 逐分支、builder null 归一、
// loader 发现顺序与 embedded 兜底、HttpClientSettings 相等性（CI 行+分支门禁 ≥98%）。
[Collection("config-global")]
public class ConfigLoadingGapTests
{
    static readonly JsonElement Keys = JsonDocument.Parse(File.OpenRead(
        Path.Combine(AppContext.BaseDirectory, "fixtures", "crypto-vectors.json"))).RootElement.GetProperty("keys");

    static string K(string name, string field) => Keys.GetProperty(name).GetProperty(field).GetString()!;

    static string ValidConfigJson(string? overrideField = null, string? overrideValue = null)
    {
        string F(string field, string jsonValue) =>
            field == overrideField ? JsonSerializer.Serialize(overrideValue!) : jsonValue;
        return "{\n" +
            "  \"appKey\": " + F("appKey", "\"demo-app\"") + ",\n" +
            "  \"suite\": " + F("suite", "\"WOP-RSA3072-SHA256\"") + ",\n" +
            "  \"merchantPrivateKey\": " + F("merchantPrivateKey", JsonSerializer.Serialize(K("rsa3072", "privatePkcs8B64"))) + ",\n" +
            "  \"platformPublicKey\": " + F("platformPublicKey", JsonSerializer.Serialize(K("rsa3072", "publicSpkiB64"))) + ",\n" +
            "  \"serverRoot\": " + F("serverRoot", "\"https://gw.example.com/gateway\"") + ",\n" +
            "  \"expiredSeconds\": 1800\n" +
            "}";
    }

    // ---------------- parser：预扫与反序列化负例 ----------------

    [Fact]
    public void Parse_空内容_拒绝()
    {
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse(null!));
        Assert.Contains("空内容", ex.Message);
    }

    [Fact]
    public void Parse_根节点非对象_拒绝()
    {
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse("[1,2]"));
        Assert.Contains("根节点须为对象", ex.Message);
    }

    [Fact]
    public void Parse_根null字面量_拒绝()
    {
        Assert.Throws<WopException>(() => ConfigJsonParser.Parse("null"));
    }

    [Fact]
    public void Parse_预扫畸形_归一拒绝()
    {
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse("{\n  \"appKey\" \"x\"\n}"));
        Assert.Contains("配置文件 JSON 解析失败", ex.Message);
    }

    [Fact]
    public void Parse_httpClient重复键_拒绝()
    {
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse(
            "{\n  \"httpClient\": {\"readTimeout\": 1, \"readTimeout\": 2}\n}"));
        Assert.Contains("readTimeout 重复", ex.Message);
    }

    [Fact]
    public void Parse_httpClient非对象_拒绝()
    {
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse(
            "{\n  \"httpClient\": 1\n}"));
        Assert.Contains("期望对象", ex.Message);
    }

    [Fact]
    public void Parse_httpClient深嵌套_拒绝()
    {
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse(
            "{\n  \"httpClient\": {\"x\": {\"y\": 1}}\n}"));
        Assert.Contains("不支持更深嵌套", ex.Message);
    }

    [Fact]
    public void Parse_值意外结束_拒绝()
    {
        // STJ 截断错误（Expected depth to be zero）归一为解析失败文案
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse("{\"appKey\": "));
        Assert.Contains("配置文件 JSON 解析失败", ex.Message);
    }

    [Fact]
    public void Parse_未知字段对象数组_跳过()
    {
        var json = ValidConfigJson().Remove(ValidConfigJson().Length - 1) +
            ",\n  \"extra\": {\"a\": [1, 2, {\"b\": true}], \"c\": null},\n  \"arr\": [\"x\", 3, false]\n}";
        var config = ConfigJsonParser.Parse(json);
        Assert.Equal("demo-app", config.AppKey);
    }

    [Fact]
    public void Parse_截断变体集_拒绝()
    {
        // 各变体分别命中预扫/SkipValue 的不同截断 throw（值未开始/对象未闭合/嵌套截断）
        foreach (var json in new[]
        {
            "{\"appKey\"",           // 值未开始即 EOF
            "{\"appKey\":\"a\"",    // 顶层对象未闭合
            "{\"extra\":{\"a\"",    // 嵌套对象值未开始
            "{\"extra\":{\"a\":1", // 嵌套对象未闭合
            "{\"extra\":[1",         // 数组未闭合
            "{\"extra\":[[\"x\"]]]", // 数组套数组递归跳过（正例）
            "{\"a\":1,}",            // 尾随逗号（AllowTrailingCommas=false）
        })
        {
            try
            {
                ConfigJsonParser.Parse(json);
                throw new InvalidOperationException("未抛异常: " + json);
            }
            catch (WopException) { }
        }
    }

    [Fact]
    public void Parse_非PropertyName令牌_对象结构非法拒绝()
    {
        // 缺逗号：Utf8JsonReader 在 token 层即拒绝（'X' is invalid after a value），
        // ScanObject 的"对象结构非法"兜底仅在 token 流错位时可达——此处验证归一拒绝即可
        Assert.Throws<WopException>(() => ConfigJsonParser.Parse("{\"appKey\":\"a\" 2}"));
        Assert.Throws<WopException>(() => ConfigJsonParser.Parse(
            ValidConfigJson().Remove(ValidConfigJson().Length - 1) + ",\n  \"extra\": {\"a\":1 2}\n}"));
    }

    [Fact]
    public void Parse_httpClient负值超时_拒绝()
    {
        foreach (var field in new[] { "connectTimeout", "readTimeout", "maxRetryCount" })
        {
            var json = ValidConfigJson().Remove(ValidConfigJson().Length - 1) +
                ",\n  \"httpClient\": {\"" + field + "\": -1}\n}";
            Assert.Throws<WopException>(() => ConfigJsonParser.Parse(json));
        }
    }

    [Fact]
    public void Parse_未闭合对象_拒绝()
    {
        Assert.Throws<WopException>(() => ConfigJsonParser.Parse(
            ValidConfigJson().Remove(ValidConfigJson().Length - 1) + ",\n  \"extra\": {\"a\": 1\n"));
    }

    [Fact]
    public void Parse_未闭合数组_拒绝()
    {
        Assert.Throws<WopException>(() => ConfigJsonParser.Parse(
            ValidConfigJson().Remove(ValidConfigJson().Length - 1) + ",\n  \"arr\": [1, 2\n"));
    }

    [Fact]
    public void Parse_反序列化类型不符_拒绝()
    {
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse(
            ValidConfigJson().Replace("\"expiredSeconds\": 1800", "\"expiredSeconds\": \"abc\"")));
        Assert.Contains("配置文件 JSON 解析失败", ex.Message);
    }

    [Fact]
    public void Parse_httpClient部分字段_走默认()
    {
        var json = ValidConfigJson().Remove(ValidConfigJson().Length - 1) +
            ",\n  \"httpClient\": {\"connectTimeout\": 1500}\n}";
        var config = ConfigJsonParser.Parse(json);
        Assert.Equal(1500, config.HttpClient.ConnectTimeout);
        Assert.Equal(HttpClientSettings.DefaultReadTimeout, config.HttpClient.ReadTimeout);
        Assert.Equal(HttpClientSettings.DefaultMaxRetryCount, config.HttpClient.MaxRetryCount);
    }

    [Fact]
    public void Parse_httpClient为null_拒绝()
    {
        // 预扫要求 httpClient 值为对象：null 与标量同罪
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse(
            ValidConfigJson().Remove(ValidConfigJson().Length - 1) + ",\n  \"httpClient\": null\n}"));
        Assert.Contains("期望对象", ex.Message);
    }

    [Fact]
    public void Parse_可空字段缺省_填空与默认()
    {
        // 全可空字段缺省 → parser 层面默认值填充，语义校验随后拦截必填
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse("{}"));
        Assert.Contains("缺少必填项", ex.Message);
        var noBackup = ConfigJsonParser.Parse(ValidConfigJson());
        Assert.Empty(noBackup.BackupServerRoots);
        Assert.Equal(WopSignProtocol.ExpiredSecondsDefault, noBackup.ExpiredSeconds);
    }

    // ---------------- validator：逐分支 ----------------

    [Theory]
    [InlineData("suite")]
    [InlineData("merchantPrivateKey")]
    [InlineData("platformPublicKey")]
    [InlineData("serverRoot")]
    public void Validate_缺必填字段_拒绝(string field)
    {
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse(ValidConfigJson(field, "  ")));
        Assert.Contains("配置文件缺少必填项: " + field, ex.Message);
    }

    [Fact]
    public void Validate_未知套件_拒绝()
    {
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse(ValidConfigJson("suite", "WOP-FAKE-1")));
        Assert.Contains("不支持的算法套件", ex.Message);
    }

    [Fact]
    public void Validate_密钥不可解析_拒绝()
    {
        var ex = Assert.Throws<WopException>(() => ConfigJsonParser.Parse(ValidConfigJson("merchantPrivateKey", "not-a-key")));
        Assert.Contains("密钥解析失败", ex.Message);
    }

    [Fact]
    public void Validate_密钥位宽与套件不符_拒绝()
    {
        // rsa2048 私钥配 3072 套件：位宽交叉校验
        var json = ValidConfigJson()
            .Replace(JsonSerializer.Serialize(K("rsa3072", "privatePkcs8B64")),
                JsonSerializer.Serialize(K("rsa2048", "privatePkcs8B64")));
        Assert.Throws<WopException>(() => ConfigJsonParser.Parse(json));
    }

    [Fact]
    public void Validate_gatewayUrl不可解析_拒绝()
    {
        var ex = Assert.Throws<WopException>(() => ConfigValidator.ValidateGatewayUrl("not a url", "serverRoot"));
        Assert.Contains("不是合法 URL", ex.Message);
    }

    [Fact]
    public void Validate_gatewayUrl空host_拒绝()
    {
        // "https:" 在 TryCreate 即失败；空 host 须用可解析但无主机形态触发
        Assert.Throws<WopException>(() => ConfigValidator.ValidateGatewayUrl("https:", "serverRoot"));
        Assert.Throws<WopException>(() => ConfigValidator.ValidateGatewayUrl("https:///gateway", "serverRoot"));
        Assert.Throws<WopException>(() => ConfigValidator.ValidateGatewayUrl("  ", "serverRoot"));
    }

    [Fact]
    public void Validate_gatewayUrl端口与去尾斜杠_归一()
    {
        Assert.Equal("https://gw.example.com:8443/gateway",
            ConfigValidator.ValidateGatewayUrl("https://GW.Example.com:8443/gateway/", "x"));
        // 无路径时归一补尾斜杠（与带路径去尾斜杠对称）
        Assert.Equal("https://gw.example.com/",
            ConfigValidator.ValidateGatewayUrl("https://gw.example.com", "x"));
    }

    [Fact]
    public void ValidateApiPath_负例集()
    {
        Assert.Throws<WopException>(() => ConfigValidator.ValidateApiPath("  "));
        var absolute = Assert.Throws<WopException>(() => ConfigValidator.ValidateApiPath("HTTPS://x.com/p"));
        Assert.Contains("不得为绝对 URL", absolute.Message);
        Assert.Throws<WopException>(() => ConfigValidator.ValidateApiPath("v1/x"));
        Assert.Throws<WopException>(() => ConfigValidator.ValidateApiPath("http://x.com/p"));
        Assert.Throws<WopException>(() => ConfigValidator.ValidateApiPath("/a?b"));
        Assert.Throws<WopException>(() => ConfigValidator.ValidateApiPath("/a#b"));
        Assert.Throws<WopException>(() => ConfigValidator.ValidateApiPath("//x"));
    }

    [Fact]
    public void JoinUrl_尾斜杠root归一()
    {
        Assert.Equal("https://gw.example.com/gateway/v1",
            ConfigValidator.JoinUrl("https://gw.example.com/gateway/", "/v1"));
    }

    // ---------------- builder 与 HttpClientSettings ----------------

    [Fact]
    public void Builder_null归一与负值拒绝()
    {
        var config = BaseBuilder().BackupServerRoots(null!).HttpClient(null!).Transport(null!).Build();
        Assert.Empty(config.BackupServerRoots);
        Assert.Equal(HttpClientSettings.Defaults, config.HttpClient);

        var ex = Assert.Throws<WopException>(() => BaseBuilder().ExpiredSeconds(0).Build());
        Assert.Contains("expiredSeconds 须为正整数", ex.Message);
        Assert.Throws<WopException>(() => BaseBuilder().HttpClient(new HttpClientSettings(-1, 30000, 3)).Build());
        Assert.Throws<WopException>(() => BaseBuilder().HttpClient(new HttpClientSettings(10000, 0, -1)).Build());
        Assert.Throws<WopException>(() => BaseBuilder().HttpClient(new HttpClientSettings(10000, 30000, -1)).Build());
        // 显式 httpClient 非空走通校验（?? 非空弧）
        var withHttp = BaseBuilder().HttpClient(new HttpClientSettings(12000, 20000, 2)).Build();
        Assert.Equal(12000, withHttp.HttpClient.ConnectTimeout);
    }

    [Fact]
    public void Builder_全字段缺省_走空串归一并拒绝()
    {
        var ex = Assert.Throws<WopException>(() => WopSdkConfig.Builder().Build());
        Assert.Contains("缺少必填项", ex.Message);
    }

    [Fact]
    public void HttpClientSettings_相等性与哈希()
    {
        var a = new HttpClientSettings(1, 2, 3);
        var b = new HttpClientSettings(1, 2, 3);
        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.NotEqual(a, new HttpClientSettings(9, 2, 3));
        Assert.NotEqual(a, new HttpClientSettings(1, 9, 3));
        Assert.NotEqual(a, new HttpClientSettings(1, 2, 9));
        Assert.False(a.Equals(null));
        Assert.True(a.Equals(a));
    }

    // ---------------- loader：发现顺序与 embedded 兜底 ----------------

    [Fact]
    public void Load_null路径_拒绝()
    {
        Assert.Throws<WopException>(() => WopConfigLoader.Load((string)null!));
        Assert.Throws<WopException>(() => WopConfigLoader.Load((FileInfo)null!));
    }

    [Fact]
    public void Load_显式缺失路径_拒绝()
    {
        var ex = Assert.Throws<WopException>(() =>
            WopConfigLoader.Load(Path.Combine(Path.GetTempPath(), "wop-missing-" + Guid.NewGuid().ToString("N") + ".json")));
        Assert.Contains("显式配置文件不可读", ex.Message);
    }

    [Fact]
    public void Load_存在但不可读_读取失败拒绝()
    {
        // FileShare.None 独占句柄：跨平台（windows CI 同路径）触发 ReadAllText IOException
        var path = Path.Combine(Path.GetTempPath(), "wop-gap-locked-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, ValidConfigJson());
        using (var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var ex = Assert.Throws<WopException>(() => WopConfigLoader.Load(path));
            Assert.Contains("配置文件读取失败", ex.Message);
        }
        File.Delete(path);
    }

    [Fact]
    public void Load_embedded缺失资源_报候选清单()
    {
        var ex = Assert.Throws<WopException>(() => WopConfigLoader.Load("embedded:no-such.json"));
        Assert.Contains("未找到可用配置文件", ex.Message);
    }

    [Fact]
    public void LoadDefault_无env无cwd候选_走embedded占位模板并拒绝()
    {
        WopConfigLoader.ClearCache();
        var env = Environment.GetEnvironmentVariable(WopConfigLoader.ConfigFileEnv);
        var envOverride = Environment.GetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride);
        var cwd = Directory.GetCurrentDirectory();
        var temp = Path.Combine(Path.GetTempPath(), "wop-gap-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnv, null);
        Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, null);
        Directory.SetCurrentDirectory(temp);
        try
        {
            var ex = Assert.Throws<WopException>(() => WopConfigLoader.LoadDefault());
            Assert.Contains("密钥解析失败", ex.Message);
        }
        finally
        {
            Directory.SetCurrentDirectory(cwd);
            Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnv, env);
            Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, envOverride);
            Directory.Delete(temp, true);
        }
    }

    [Fact]
    public void LoadDefault_空文件候选_跳过走embedded()
    {
        WopConfigLoader.ClearCache();
        var cwd = Directory.GetCurrentDirectory();
        var temp = Path.Combine(Path.GetTempPath(), "wop-gap-empty-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        File.WriteAllText(Path.Combine(temp, "wopSdkConfig.json"), "");
        var env = Environment.GetEnvironmentVariable(WopConfigLoader.ConfigFileEnv);
        var envOverride = Environment.GetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride);
        Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnv, null);
        Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, null);
        Directory.SetCurrentDirectory(temp);
        try
        {
            Assert.Throws<WopException>(() => WopConfigLoader.LoadDefault());
        }
        finally
        {
            Directory.SetCurrentDirectory(cwd);
            Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnv, env);
            Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, envOverride);
            Directory.Delete(temp, true);
        }
    }

    [Fact]
    public void LoadDefault_cwd子目录候选_命中()
    {
        WopConfigLoader.ClearCache();
        var cwd = Directory.GetCurrentDirectory();
        var temp = Path.Combine(Path.GetTempPath(), "wop-gap-sub-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(temp, "config"));
        File.WriteAllText(Path.Combine(temp, "config", "wopSdkConfig.json"), ValidConfigJson());
        var env = Environment.GetEnvironmentVariable(WopConfigLoader.ConfigFileEnv);
        var envOverride = Environment.GetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride);
        Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnv, null);
        Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, null);
        Directory.SetCurrentDirectory(temp);
        try
        {
            Assert.Equal("demo-app", WopConfigLoader.LoadDefault().AppKey);
        }
        finally
        {
            Directory.SetCurrentDirectory(cwd);
            Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnv, env);
            Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, envOverride);
            Directory.Delete(temp, true);
        }
    }

    [Fact]
    public void LoadDefault_次级env变量_命中()
    {
        WopConfigLoader.ClearCache();
        var path = Path.Combine(Path.GetTempPath(), "wop-gap-env-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, ValidConfigJson());
        var envOverride = Environment.GetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride);
        Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, null);
        Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnv, path);
        try
        {
            Assert.Equal("demo-app", WopConfigLoader.LoadDefault().AppKey);
        }
        finally
        {
            Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnv, null);
            Environment.SetEnvironmentVariable(WopConfigLoader.ConfigFileEnvOverride, envOverride);
            File.Delete(path);
        }
    }

    [Fact]
    public void GatewayResponseException_nullBody_零字节快照()
    {
        var ex = new WopGatewayResponseException(502, null);
        Assert.Equal(502, ex.StatusCode);
        Assert.Empty(ex.Body);
        Assert.Contains("0 字节", ex.Message);
    }

    static WopSdkConfigBuilder BaseBuilder() =>
        WopSdkConfig.Builder()
            .AppKey("demo-app")
            .Suite("WOP-RSA3072-SHA256")
            .MerchantPrivateKey(K("rsa3072", "privatePkcs8B64"))
            .PlatformPublicKey(K("rsa3072", "publicSpkiB64"))
            .ServerRoot("https://gw.example.com/gateway");
}
