using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace Wop.Sdk;

/// <summary>可插拔 HTTP 适配层（spec §1.1 Q1：协议核心纯函数，传输可替换）。
/// 商户自带栈时直接消费 RequestDraft，无需本接口。</summary>
public interface IWopTransport
{
    /// <summary>发送请求草稿，返回归一化响应。</summary>
    TransportResponse Send(RequestDraft draft);
}

/// <summary>适配层归一化的响应。</summary>
public sealed class TransportResponse
{
    /// <summary>HTTP 状态码。</summary>
    public int StatusCode { get; }

    /// <summary>响应头（多值以逗号连接）。</summary>
    public IReadOnlyDictionary<string, string> Headers { get; }

    /// <summary>响应体字节。</summary>
    public byte[] Body { get; }

    public TransportResponse(int statusCode, IReadOnlyDictionary<string, string> headers, byte[] body)
    {
        StatusCode = statusCode;
        Headers = headers;
        Body = body;
    }
}

/// <summary>默认 HttpClient 适配器（DelegatingHandler 可插拔：
/// 构造注入 HttpMessageHandler / HttpClient 即可替换重试、日志、连接池等行为）。</summary>
public sealed class HttpClientTransport : IWopTransport
{
    /// <summary>响应体读取上限（10MB 线上体上限 + 信封膨胀余量，防失控读）。</summary>
    public const int MaxResponseBytes = 11 << 20;

    private readonly HttpClient _client;
    private readonly string _baseUrl;

    /// <summary>以指定 HttpClient 与网关基地址构造。</summary>
    public HttpClientTransport(HttpClient client, string baseUrl)
    {
        _client = client ?? throw new WopException(WopErrorCode.Config, "HttpClient 为空");
        _baseUrl = baseUrl ?? "";
    }

    /// <summary>以可插拔 HttpMessageHandler（含 DelegatingHandler）构造。</summary>
    public HttpClientTransport(HttpMessageHandler handler, string baseUrl)
        : this(new HttpClient(handler, disposeHandler: false), baseUrl)
    {
    }

    /// <summary>以网关基地址构造（§7.4.1 不跟随重定向）。</summary>
    public HttpClientTransport(string baseUrl)
        : this(CreateDefaultHttpClient(), baseUrl)
    {
    }

    /// <summary>按配置创建默认 HttpClient 适配器（AllowAutoRedirect=false）。</summary>
    public static HttpClientTransport Create(string baseUrl, HttpClientSettings settings)
    {
        var client = CreateHttpClient(settings);
        return new HttpClientTransport(client, baseUrl);
    }

    private static HttpClient CreateDefaultHttpClient() =>
        CreateHttpClient(HttpClientSettings.Defaults);

    private static HttpClient CreateHttpClient(HttpClientSettings settings)
    {
        var handler = CreateHandler(settings);
        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromMilliseconds(settings.ReadTimeout),
        };
    }

    private static HttpMessageHandler CreateHandler(HttpClientSettings settings)
    {
#if NET5_0_OR_GREATER
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromMilliseconds(settings.ConnectTimeout),
        };
#else
        return new HttpClientHandler { AllowAutoRedirect = false };
#endif
    }

    /// <summary>发送：§7.7 字符串拼接 serverRoot + path；有 body 时设置 Content-Type: application/json。</summary>
    public TransportResponse Send(RequestDraft draft)
    {
        var target = ConfigValidator.JoinUrl(_baseUrl, draft.Path);
        Uri uri;
        try
        {
            uri = new Uri(target, UriKind.Absolute);
        }
        catch (Exception)
        {
            throw new WopException(WopErrorCode.Config, "请求地址非法：" + target);
        }

        using var request = new HttpRequestMessage(new HttpMethod(draft.Method), uri);
        foreach (var (name, value) in draft.Headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }
        if (draft.WireBody is { Length: > 0 })
        {
            request.Content = new ByteArrayContent(draft.WireBody);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }

        HttpResponseMessage response;
        try
        {
            response = _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
        }
        catch (Exception e)
        {
            throw new WopException(WopErrorCode.Config, "HTTP 发送失败：" + e.Message);
        }
        using (response)
        {
            byte[] body;
            try
            {
                using var limited = new LimitStream(response.Content.ReadAsStreamAsync().GetAwaiter().GetResult(),
                    MaxResponseBytes + 1);
                using var ms = new MemoryStream();
                limited.CopyTo(ms);
                body = ms.ToArray();
            }
            catch (WopException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new WopException(WopErrorCode.Config, "读取响应体失败：" + e.Message);
            }
            if (body.Length > MaxResponseBytes)
            {
                throw new WopException(WopErrorCode.Protocol,
                    "响应体超过 " + MaxResponseBytes + " 字节上限");
            }
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (name, values) in response.Headers)
            {
                headers[name] = string.Join(",", values);
            }
            foreach (var (name, values) in response.Content.Headers)
            {
                headers[name] = string.Join(",", values);
            }
            return new TransportResponse((int)response.StatusCode, headers, body);
        }
    }

    /// <summary>带读取上限的流（限额类：读中止，D5 精神）。</summary>
    private sealed class LimitStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _limit;
        private long _read;

        internal LimitStream(Stream inner, long limit)
        {
            _inner = inner;
            _limit = limit;
        }

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        /// <summary>读入缓冲区并累计读取量，超限即中止（协议类错误，防失控读）。</summary>
        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = _inner.Read(buffer, offset, count);
            _read += n;
            if (_read > _limit)
            {
                throw new WopException(WopErrorCode.Protocol, "响应体超限");
            }
            return n;
        }

        /// <summary>不支持：只读流。</summary>
        public override void Flush() => throw new NotSupportedException();
        /// <summary>不支持：不可定位流。</summary>
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        /// <summary>不支持：只读流。</summary>
        public override void SetLength(long value) => throw new NotSupportedException();
        /// <summary>不支持：只读流。</summary>
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
