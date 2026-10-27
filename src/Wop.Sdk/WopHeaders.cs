namespace Wop.Sdk;

/// <summary>协议 Header 名称（x-wop- 前缀，与网关 GatewayConstants 对齐）。</summary>
public static class WopHeaders
{
    public const string AppKey = "x-wop-appkey";
    public const string Sign = "x-wop-sign";
    public const string ContentDigest = "x-wop-content-digest";
    public const string Timestamp = "x-wop-timestamp";
    public const string Nonce = "x-wop-nonce";
    public const string Encrypt = "x-wop-encrypt";

    /// <summary>ISV 子商户身份头（ISV D-13）：值 = 子商户 plf_co_id；
    /// 存在即必须入签，缺席 = 应用自身身份（AC-20）。</summary>
    public const string SubMchId = "x-wop-sub-mch-id";

    /// <summary>商户请求标识透传头（wop-specs 附录 I：唯一可选透传头，恒不入签）。</summary>
    public const string RequestId = "x-wop-request-id";
}

/// <summary>签名协议常量（spec §7 / 网关 GatewayConstants）。</summary>
public static class WopSignProtocol
{
    /// <summary>签名协议版本。</summary>
    public const string Version = "v1";

    /// <summary>出站签名默认有效时长（秒）。</summary>
    public const long ExpiredSecondsDefault = 1800;

    /// <summary>expiredSeconds 允许上限（秒），防超大窗口拉长重放风险。</summary>
    public const long ExpiredSecondsMax = 86400;
}
