using System;

namespace Wop.Sdk;

/// <summary>网关非 2xx 响应（§7.5）；携带 statusCode 与 body 快照，不进入验签。</summary>
public sealed class WopGatewayResponseException : Exception
{
    /// <summary>HTTP 状态码。</summary>
    public int StatusCode { get; }

    /// <summary>响应体快照。</summary>
    public byte[] Body { get; }

    /// <summary>构造网关响应异常。</summary>
    public WopGatewayResponseException(int statusCode, byte[]? body)
        : base("WOP 网关返回 HTTP " + statusCode + "（响应体 " + (body?.Length ?? 0) + " 字节）")
    {
        StatusCode = statusCode;
        Body = body == null ? Array.Empty<byte>() : (byte[])body.Clone();
    }
}
