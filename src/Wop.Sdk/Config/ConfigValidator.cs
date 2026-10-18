using System;
using System.Collections.Generic;

namespace Wop.Sdk;

/// <summary>§3.4 语义校验与字段归一化。</summary>
internal static class ConfigValidator
{
    /// <summary>校验并归一化配置快照。</summary>
    internal static WopSdkConfig ValidateAndNormalize(WopSdkConfig raw)
    {
        if (string.IsNullOrWhiteSpace(raw.AppKey))
        {
            throw Config("配置文件缺少必填项: appKey");
        }
        if (string.IsNullOrWhiteSpace(raw.Suite))
        {
            throw Config("配置文件缺少必填项: suite");
        }
        if (string.IsNullOrWhiteSpace(raw.MerchantPrivateKey))
        {
            throw Config("配置文件缺少必填项: merchantPrivateKey");
        }
        if (string.IsNullOrWhiteSpace(raw.PlatformPublicKey))
        {
            throw Config("配置文件缺少必填项: platformPublicKey");
        }
        if (string.IsNullOrWhiteSpace(raw.ServerRoot))
        {
            throw Config("配置文件缺少必填项: serverRoot");
        }
        if (raw.ExpiredSeconds <= 0)
        {
            throw Config("expiredSeconds 须为正整数");
        }

        AlgorithmSuite suite;
        try
        {
            suite = AlgorithmSuite.Parse(raw.Suite);
        }
        catch (WopException e) when (e.ErrorCode is WopErrorCode.SuiteParse or WopErrorCode.SuiteUnsupported)
        {
            throw Config("不支持的算法套件: " + raw.Suite);
        }

        try
        {
            AsymmetricKeyMaterial.ParsePrivate(raw.MerchantPrivateKey, suite);
            AsymmetricKeyMaterial.ParsePublic(raw.PlatformPublicKey, suite);
        }
        catch (WopException e)
        {
            throw Config("密钥解析失败: " + e.Message);
        }

        var serverRoot = ValidateGatewayUrl(raw.ServerRoot, "serverRoot");
        var backups = new List<string>();
        for (var i = 0; i < raw.BackupServerRoots.Count; i++)
        {
            backups.Add(ValidateGatewayUrl(raw.BackupServerRoots[i], "backupServerRoots[" + i + "]"));
        }

        var http = raw.HttpClient ?? HttpClientSettings.Defaults;
        if (http.ConnectTimeout <= 0 || http.ReadTimeout <= 0 || http.MaxRetryCount < 0)
        {
            throw Config("配置字段 httpClient 类型非法: 超时须为正整数，maxRetryCount 须非负");
        }

        return new WopSdkConfig(
            raw.AppKey.Trim(),
            raw.Suite.Trim(),
            raw.MerchantPrivateKey.Trim(),
            raw.PlatformPublicKey.Trim(),
            serverRoot,
            backups,
            raw.ExpiredSeconds,
            http,
            raw.Transport);
    }

    /// <summary>K20：HTTPS 绝对 URL，拒绝 query/fragment。</summary>
    internal static string ValidateGatewayUrl(string value, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw Config(fieldName + " 不是合法 URL: " + value);
        }

        var trimmed = value.Trim();
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            throw Config(fieldName + " 不是合法 URL: " + trimmed);
        }
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw Config(fieldName + " 须为 HTTPS 绝对 URL: " + trimmed);
        }
        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw Config(fieldName + " 不得含 query 或 fragment: " + trimmed);
        }
        if (string.IsNullOrEmpty(uri.Host))
        {
            throw Config(fieldName + " 不是合法 URL: " + trimmed);
        }

        var path = uri.AbsolutePath;
        if (path.Length > 1 && path.EndsWith("/", StringComparison.Ordinal))
        {
            path = path.TrimEnd('/');
        }
        else if (path.Length == 0)
        {
            path = "";
        }

        var portPart = uri.IsDefaultPort ? "" : ":" + uri.Port;
        var normalized = "https://" + uri.Host.ToLowerInvariant() + portPart + path;
        return normalized;
    }

    /// <summary>§7.7 API path 语法校验。</summary>
    internal static void ValidateApiPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw Config("请求 path 为空");
        }
        // 绝对 URL 检查须先于 / 前缀检查，否则对 "https://..." 永远只报前缀错
        if (path.StartsWith("http:", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("https:", StringComparison.OrdinalIgnoreCase))
        {
            throw Config("path 不得为绝对 URL: " + path);
        }
        if (!path.StartsWith("/", StringComparison.Ordinal))
        {
            throw Config("path 须以 / 开头: " + path);
        }
        if (path.StartsWith("//", StringComparison.Ordinal))
        {
            throw Config("path 不得 // 开头: " + path);
        }
        // netstandard2.0 无 Contains(string, StringComparison) 重载，用 IndexOf 等价判定
        if (path.IndexOf("?", StringComparison.Ordinal) >= 0 || path.IndexOf("#", StringComparison.Ordinal) >= 0)
        {
            throw Config("path 不得含 query 或 fragment: " + path);
        }
    }

    /// <summary>§7.7 字符串拼接 serverRoot + path。</summary>
    internal static string JoinUrl(string serverRoot, string path)
    {
        ValidateApiPath(path);
        var root = serverRoot.EndsWith("/", StringComparison.Ordinal)
            ? serverRoot.Substring(0, serverRoot.Length - 1)
            : serverRoot;
        return root + path;
    }

    /// <summary>统一构造 configuration 异常（消息含字段名，§3.4）。</summary>
    private static WopException Config(string message) =>
        new(WopErrorCode.Config, message);
}
