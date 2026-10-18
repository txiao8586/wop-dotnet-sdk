using System;
using System.Collections.Generic;
using System.Text;

namespace Wop.Sdk;

/// <summary>canonicalRequest 构造（F2）：5 段 '\n' 拼接；
/// header 值 Java-URLEncoder 语义（空格 → %20 等）。</summary>
public static class CanonicalRequest
{
    /// <summary>构造规范标头：名称 lowercase + TrimAll + urlencode，值 TrimAll + urlencode，
    /// 按名称 ASCII 升序，行间 '\n' 连接，尾行不加 '\n'。</summary>
    public static string CanonicalHeaders(IReadOnlyDictionary<string, string> headers)
    {
        if (headers.Count == 0)
        {
            return "";
        }
        var sorted = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var kv in headers)
        {
            sorted[Codec.TrimAll(kv.Key).ToLowerInvariant()] = Codec.TrimAll(kv.Value);
        }
        var sb = new StringBuilder();
        var first = true;
        foreach (var kv in sorted)
        {
            if (!first)
            {
                sb.Append('\n');
            }
            first = false;
            sb.Append(Codec.UrlEncodeJava(kv.Key)).Append(':').Append(Codec.UrlEncodeJava(kv.Value));
        }
        return sb.ToString();
    }

    /// <summary>组装 5 段规范请求：
    /// authString\nhttpRequestMethod\ncanonicalURI\ncanonicalQueryString\ncanonicalHeaders。
    /// POST 的 canonicalQueryString 为空串，分隔空行不可省略；method 统一大写。</summary>
    public static string Build(string authString, string method, string canonicalUri,
        string canonicalQueryString, string canonicalHeaders)
    {
        return nz(authString) + "\n" +
               nz(method).Trim().ToUpperInvariant() + "\n" +
               nz(canonicalUri) + "\n" +
               nz(canonicalQueryString) + "\n" +
               nz(canonicalHeaders);
    }
    /// <summary>空值归一为空串（canonical 段防御）。</summary>
    private static string nz(string? s) => s ?? "";
}
