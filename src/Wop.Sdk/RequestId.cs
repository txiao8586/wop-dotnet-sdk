using System;
using System.Security.Cryptography;
using System.Text;

namespace Wop.Sdk;

/// <summary>
/// 商户请求标识（wop-specs 附录 I：x-wop-request-id 透传头）。
///
/// - I1：唯一出向可选透传头，恒不入签（签名落盘后写入）；
/// - I2：构造即校验——trim 前按原值扫描控制字符（&lt; 0x20 或 == 0x7F，含 CR/LF/NUL/DEL，
///   防头注入）、trim（G2 TrimAll 同集：空格、\t、\n、\x0B、\f、\r；不用 Trim() 的
///   Unicode 空白超集）后为空视为未设置、显式值含非 ASCII（&gt; 0x7F）拒
///   （.NET HttpClient 头值按 Latin-1 写出，CJK 到网关必乱码）、
///   UTF-8 字节 &gt; 128 拒（网关 header 缓冲按字节计）；
/// - I3：未传/空白 → 缺省生成 UUID 去连字符（小写 32 hex，v4 语义），最终头恒存在。
/// </summary>
internal static class RequestId
{
    /// <summary>附录 I/I2 trim 集 = G2 TrimAll 空白类。</summary>
    private static readonly char[] TrimChars = { ' ', '\t', '\n', '\x0B', '\f', '\r' };

    /// <summary>缺省生成器（可整体替换——测试确定性锚，与 clock/nonce 注入同级）。</summary>
    internal static Func<string> Generator { get; set; } = GenerateDefault;

    /// <summary>缺省生成：UUID 去连字符（小写 32 位 hex，v4 语义）。</summary>
    internal static string GenerateDefault()
    {
        var b = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(b);
        }
        b[6] = (byte)((b[6] & 0x0F) | 0x40); // version 4
        b[8] = (byte)((b[8] & 0x3F) | 0x80); // RFC 4122 variant
        // BitConverter 兼容 netstandard2.0（Convert.ToHexString 为 .NET 5+ API）
        return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant();
    }

    /// <summary>
    /// 校验并归一化（附录 I/I2，构造即拒，configuration 类）。
    /// 返回 trim 后上行值；null = 未设置（调用方走缺省生成）。
    /// </summary>
    internal static string? Resolve(string? raw)
    {
        // netstandard2.0 的 string.IsNullOrEmpty 不带 [NotNullWhen] 流注解，用显式判空保流动分析
        if (raw == null || raw.Length == 0)
        {
            return null;
        }
        foreach (var ch in raw)
        {
            if (ch < 0x20 || ch == 0x7F)
            {
                throw new WopException(WopErrorCode.Config,
                    "requestId 含控制字符（防头注入）: " + (int)ch);
            }
        }
        var trimmed = raw.Trim(TrimChars);
        if (trimmed.Length == 0)
        {
            return null;
        }
        foreach (var ch in trimmed)
        {
            if (ch > 0x7F)
            {
                // shortcut: 非ASCII显式值在.NET传输层Latin-1乱码,待网关支持UTF-8头后放开
                throw new WopException(WopErrorCode.Config,
                    "requestId 含非 ASCII 字符（.NET HttpClient 头值按 Latin-1 写出，上行必乱码）");
            }
        }
        var utf8Len = Encoding.UTF8.GetByteCount(trimmed);
        if (utf8Len > 128)
        {
            throw new WopException(WopErrorCode.Config,
                "requestId UTF-8 字节长度不能超过 128（实际 " + utf8Len + "）");
        }
        return trimmed;
    }
}
