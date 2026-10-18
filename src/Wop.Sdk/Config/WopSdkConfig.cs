using System;
using System.Collections.Generic;

namespace Wop.Sdk;

/// <summary>配置不可变快照（§3，camelCase 字段与 JSON 一致）。</summary>
public sealed class WopSdkConfig
{
    /// <summary>商户 appKey。</summary>
    public string AppKey { get; }

    /// <summary>算法套件。</summary>
    public string Suite { get; }

    /// <summary>商户私钥（PEM 或 Base64 单行）。</summary>
    public string MerchantPrivateKey { get; }

    /// <summary>平台公钥（PEM 或 Base64 单行）。</summary>
    public string PlatformPublicKey { get; }

    /// <summary>主网关根地址（HTTPS，已归一化）。</summary>
    public string ServerRoot { get; }

    /// <summary>备用网关根地址（有序）。</summary>
    public IReadOnlyList<string> BackupServerRoots { get; }

    /// <summary>出向签名有效窗口（秒）。</summary>
    public long ExpiredSeconds { get; }

    /// <summary>HTTP 客户端全局设置。</summary>
    public HttpClientSettings HttpClient { get; }

    /// <summary>可选注入传输；null 时由 <see cref="WopClient.FromConfig"/> 创建默认 HttpClient 适配器。</summary>
    public IWopTransport? Transport { get; }

    internal WopSdkConfig(
        string appKey,
        string suite,
        string merchantPrivateKey,
        string platformPublicKey,
        string serverRoot,
        IReadOnlyList<string> backupServerRoots,
        long expiredSeconds,
        HttpClientSettings httpClient,
        IWopTransport? transport)
    {
        AppKey = appKey;
        Suite = suite;
        MerchantPrivateKey = merchantPrivateKey;
        PlatformPublicKey = platformPublicKey;
        ServerRoot = serverRoot;
        BackupServerRoots = backupServerRoots;
        ExpiredSeconds = expiredSeconds;
        HttpClient = httpClient;
        Transport = transport;
    }

    /// <summary>K16：日志/toString 私钥打码。</summary>
    public override string ToString() =>
        "WopSdkConfig[appKey=" + AppKey + ", suite=" + Suite
        + ", merchantPrivateKey=****, platformPublicKey=****"
        + ", serverRoot=" + ServerRoot
        + ", backupServerRoots=" + string.Join(",", BackupServerRoots)
        + ", expiredSeconds=" + ExpiredSeconds
        + ", httpClient=" + HttpClient.ConnectTimeout + "/" + HttpClient.ReadTimeout
        + "/" + HttpClient.MaxRetryCount + "]";

    /// <summary>程序化构造（K11），Build 执行与 JSON 路径等价的 §3.4 校验。</summary>
    public static WopSdkConfigBuilder Builder() => new();
}

/// <summary><see cref="WopSdkConfig"/> 程序化构建器。</summary>
public sealed class WopSdkConfigBuilder
{
    private string? _appKey;
    private string? _suite;
    private string? _merchantPrivateKey;
    private string? _platformPublicKey;
    private string? _serverRoot;
    private IReadOnlyList<string> _backupServerRoots = Array.Empty<string>();
    private long _expiredSeconds = WopSignProtocol.ExpiredSecondsDefault;
    private HttpClientSettings _httpClient = HttpClientSettings.Defaults;
    private IWopTransport? _transport;

    /// <summary>商户 appKey。</summary>
    public WopSdkConfigBuilder AppKey(string appKey)
    {
        _appKey = appKey;
        return this;
    }

    /// <summary>算法套件。</summary>
    public WopSdkConfigBuilder Suite(string suite)
    {
        _suite = suite;
        return this;
    }

    /// <summary>商户私钥。</summary>
    public WopSdkConfigBuilder MerchantPrivateKey(string merchantPrivateKey)
    {
        _merchantPrivateKey = merchantPrivateKey;
        return this;
    }

    /// <summary>平台公钥。</summary>
    public WopSdkConfigBuilder PlatformPublicKey(string platformPublicKey)
    {
        _platformPublicKey = platformPublicKey;
        return this;
    }

    /// <summary>主网关根地址。</summary>
    public WopSdkConfigBuilder ServerRoot(string serverRoot)
    {
        _serverRoot = serverRoot;
        return this;
    }

    /// <summary>备用网关根地址。</summary>
    public WopSdkConfigBuilder BackupServerRoots(IReadOnlyList<string> backupServerRoots)
    {
        _backupServerRoots = backupServerRoots ?? Array.Empty<string>();
        return this;
    }

    /// <summary>出向签名有效窗口（秒）。</summary>
    public WopSdkConfigBuilder ExpiredSeconds(long expiredSeconds)
    {
        _expiredSeconds = expiredSeconds;
        return this;
    }

    /// <summary>HTTP 客户端全局设置。</summary>
    public WopSdkConfigBuilder HttpClient(HttpClientSettings httpClient)
    {
        _httpClient = httpClient ?? HttpClientSettings.Defaults;
        return this;
    }

    /// <summary>可选传输注入。</summary>
    public WopSdkConfigBuilder Transport(IWopTransport? transport)
    {
        _transport = transport;
        return this;
    }

    /// <summary>构建并执行 §3.4 校验。</summary>
    public WopSdkConfig Build()
    {
        var raw = new WopSdkConfig(
            _appKey ?? "",
            _suite ?? "",
            _merchantPrivateKey ?? "",
            _platformPublicKey ?? "",
            _serverRoot ?? "",
            _backupServerRoots,
            _expiredSeconds,
            _httpClient,
            _transport);
        return ConfigValidator.ValidateAndNormalize(raw);
    }
}
