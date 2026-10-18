using System;

namespace Wop.Sdk;

/// <summary>HTTP 客户端全局设置（§3.3 httpClient 对象，不可变）。</summary>
public sealed class HttpClientSettings
{
    /// <summary>默认连接超时（毫秒）。</summary>
    public const int DefaultConnectTimeout = 10_000;

    /// <summary>默认读超时（毫秒）。</summary>
    public const int DefaultReadTimeout = 30_000;

    /// <summary>默认跨域名重试上限。</summary>
    public const int DefaultMaxRetryCount = 3;

    /// <summary>TCP 连接超时（毫秒）。</summary>
    public int ConnectTimeout { get; }

    /// <summary>读响应超时（毫秒）。</summary>
    public int ReadTimeout { get; }

    /// <summary>跨域名重试上限（仅全局）。</summary>
    public int MaxRetryCount { get; }

    /// <summary>构造 HTTP 客户端设置。</summary>
    public HttpClientSettings(int connectTimeout, int readTimeout, int maxRetryCount)
    {
        ConnectTimeout = connectTimeout;
        ReadTimeout = readTimeout;
        MaxRetryCount = maxRetryCount;
    }

    /// <summary>默认超时与重试上限。</summary>
    public static HttpClientSettings Defaults { get; } =
        new(DefaultConnectTimeout, DefaultReadTimeout, DefaultMaxRetryCount);

    /// <inheritdoc />
    public override bool Equals(object? obj) =>
        obj is HttpClientSettings other
        && ConnectTimeout == other.ConnectTimeout
        && ReadTimeout == other.ReadTimeout
        && MaxRetryCount == other.MaxRetryCount;

    /// <inheritdoc />
    // netstandard2.0 无 System.HashCode（2.1+ API），手写组合
    /// <summary>手写哈希组合（netstandard2.0 无 System.HashCode）。</summary>
    public override int GetHashCode()
    {
        unchecked
        {
            var h = 17;
            h = h * 31 + ConnectTimeout.GetHashCode();
            h = h * 31 + ReadTimeout.GetHashCode();
            h = h * 31 + MaxRetryCount.GetHashCode();
            return h;
        }
    }
}
