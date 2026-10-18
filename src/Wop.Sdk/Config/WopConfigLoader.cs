using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace Wop.Sdk;

/// <summary>配置加载入口（§4，线程安全）。</summary>
public static class WopConfigLoader
{
    /// <summary>优先级 1：显式配置文件路径环境变量。</summary>
    public const string ConfigFileEnvOverride = "WOP_SDK_CONFIG_FILE";

    /// <summary>优先级 2：配置文件路径环境变量。</summary>
    public const string ConfigFileEnv = "WOP_SDK_CONFIG";

    private const string EmbeddedPrefix = "embedded:";
    private const string PackagedConfig = "config/wopSdkConfig.json";

    private static readonly object CacheLock = new();
    private static readonly Dictionary<string, WopSdkConfig> Cache = new(StringComparer.Ordinal);

    /// <summary>按 §4.2 自动发现并加载；同一位置缓存解析结果。</summary>
    public static WopSdkConfig LoadDefault()
    {
        var discovery = Discover();
        return LoadCached(discovery.CacheKey, discovery.ReadUtf8);
    }

    /// <summary>显式位置：embedded: 前缀读嵌入资源，其余为文件系统路径。</summary>
    public static WopSdkConfig Load(string location)
    {
        if (location == null)
        {
            throw new WopException(WopErrorCode.Config, "location 为空");
        }
        if (location.StartsWith(EmbeddedPrefix, StringComparison.Ordinal))
        {
            var resource = location.Substring(EmbeddedPrefix.Length);
            return LoadCached(EmbeddedPrefix + resource, () => ReadEmbedded(resource));
        }
        return Load(new FileInfo(location));
    }

    /// <summary>显式文件系统路径。</summary>
    public static WopSdkConfig Load(FileInfo path)
    {
        if (path == null)
        {
            throw new WopException(WopErrorCode.Config, "path 为空");
        }
        var normalized = path.FullName;
        return LoadCached("file:" + normalized, () => ReadFile(path, explicitPath: true));
    }

    /// <summary>清除加载缓存（测试 / 配置轮换编排）。</summary>
    public static void ClearCache()
    {
        lock (CacheLock)
        {
            Cache.Clear();
        }
    }

    /// <summary>以规范化位置为 key 的缓存读取（K13：无自动失效，clearCache 显式清）。</summary>
    private static WopSdkConfig LoadCached(string key, Func<string> supplier)
    {
        lock (CacheLock)
        {
            if (Cache.TryGetValue(key, out var cached))
            {
                return cached;
            }
            var parsed = ConfigJsonParser.Parse(supplier());
            Cache[key] = parsed;
            return parsed;
        }
    }

    /// <summary>§4.2 六来源发现顺序：显式 env 优先，全部未命中报候选清单。</summary>
    private static DiscoveryResult Discover()
    {
        var overridePath = Environment.GetEnvironmentVariable(ConfigFileEnvOverride);
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            return DiscoveryResult.File(new FileInfo(overridePath.Trim()), explicitPath: true);
        }

        var envPath = Environment.GetEnvironmentVariable(ConfigFileEnv);
        if (!string.IsNullOrWhiteSpace(envPath))
        {
            return DiscoveryResult.File(new FileInfo(envPath.Trim()), explicitPath: true);
        }

        var cwd = Directory.GetCurrentDirectory();
        var candidates = new[]
        {
            Path.Combine(cwd, "config", "wopSdkConfig.json"),
            Path.Combine(cwd, "wopSdkConfig.json"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".wop", "wopSdkConfig.json"),
        };
        foreach (var candidate in candidates)
        {
            var file = new FileInfo(candidate);
            if (file.Exists && file.Length > 0)
            {
                return DiscoveryResult.File(file, explicitPath: false);
            }
        }

        return DiscoveryResult.Embedded(PackagedConfig);
    }

    /// <summary>读文件（UTF-8 剥 BOM，空文件报错，§4.3）。</summary>
    private static string ReadFile(FileInfo file, bool explicitPath)
    {
        if (!file.Exists)
        {
            throw new WopException(WopErrorCode.Config,
                explicitPath ? "显式配置文件不可读: " + file.FullName : "配置文件不存在: " + file.FullName);
        }
        try
        {
            return File.ReadAllText(file.FullName, Encoding.UTF8);
        }
        catch (Exception e)
        {
            throw new WopException(WopErrorCode.Config, "配置文件读取失败: " + file.FullName + ": " + e.Message);
        }
    }

    /// <summary>读打包资源（K6 兜底来源）。</summary>
    private static string ReadEmbedded(string resourceName)
    {
        var assembly = typeof(WopConfigLoader).GetTypeInfo().Assembly;
        var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null)
        {
            var cwd = Directory.GetCurrentDirectory();
            var tried = string.Join(", ",
                Path.Combine(cwd, "config", "wopSdkConfig.json"),
                Path.Combine(cwd, "wopSdkConfig.json"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".wop", "wopSdkConfig.json"),
                "embedded:" + resourceName);
            throw new WopException(WopErrorCode.Config,
                "未找到可用配置文件，已尝试: " + tried);
        }
        using (stream)
        using (var reader = new StreamReader(stream, Encoding.UTF8))
        {
            return reader.ReadToEnd();
        }
    }

    private sealed class DiscoveryResult
    {
        private readonly Func<string> _reader;

        internal string CacheKey { get; }
        internal bool ExplicitPath { get; }

        private DiscoveryResult(string cacheKey, Func<string> reader, bool explicitPath)
        {
            CacheKey = cacheKey;
            _reader = reader;
            ExplicitPath = explicitPath;
        }

        /// <summary>构造文件来源候选（显式指定不可读即不容忍，§4.2）。</summary>
    internal static DiscoveryResult File(FileInfo file, bool explicitPath) =>
            new("file:" + file.FullName, () => ReadFile(file, explicitPath), explicitPath);

        /// <summary>构造打包资源候选（兜底，命中即用）。</summary>
    internal static DiscoveryResult Embedded(string resource) =>
            new(EmbeddedPrefix + resource, () => ReadEmbedded(resource), false);

        internal string ReadUtf8() => _reader();
    }
}
