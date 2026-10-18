using System;

namespace Wop.Sdk;

/// <summary>算法体系族（crypto-strategy-spec §2.2）：国际（RSA）与国密（SM2）。</summary>
public enum SuiteFamily
{
    Rsa,
    Sm2,
}

/// <summary>算法套件（spec §4.4 / §3.2 推导规则）：securityReq 一次性原子解析
/// （I6）的不可变值类型，四维算法推导结果与协议常量集中于此。
/// 映射集中注册于代码，无运行时配置入口（D13）。</summary>
public sealed class AlgorithmSuite
{
    /// <summary>原始套件标识串（WOP-&lt;密钥算法&gt;-&lt;摘要算法&gt;）。</summary>
    public string SecurityReq { get; }

    /// <summary>密钥算法族。</summary>
    public SuiteFamily Family { get; }

    /// <summary>RSA 密钥位数（3072/4096）；SM2 套件恒 0。</summary>
    public int KeyBits { get; }

    /// <summary>推导后的签名算法名（①）。</summary>
    public string SignAlgorithm { get; }

    /// <summary>L2 报文对称算法名（②，dek alg 段）。</summary>
    public string MessageAlgorithm { get; }

    /// <summary>DEK 非对称包装算法名（③）。</summary>
    public string KeyWrapAlgorithm { get; }

    /// <summary>x-wop-content-digest 算法标签（④，D2）。</summary>
    public string DigestTag { get; }

    private AlgorithmSuite(string securityReq, SuiteFamily family, int keyBits,
        string signAlgorithm, string messageAlgorithm, string keyWrapAlgorithm, string digestTag)
    {
        SecurityReq = securityReq;
        Family = family;
        KeyBits = keyBits;
        SignAlgorithm = signAlgorithm;
        MessageAlgorithm = messageAlgorithm;
        KeyWrapAlgorithm = keyWrapAlgorithm;
        DigestTag = digestTag;
    }

    /// <summary>是否为国密 SM2 族套件。</summary>
    public bool IsSm2 => Family == SuiteFamily.Sm2;

    /// <summary>对称密钥（CEK）长度（spec §3.3②）：AES-256 → 32B，SM4 → 16B。</summary>
    public int CekLength => IsSm2 ? 16 : 32;

    /// <summary>签名定长（spec §3.3①：定长编码使格式校验可前置）：
    /// RSA = 密钥字节数（2048→256B，3072→384B，4096→512B）；SM2 = r‖s 64B。</summary>
    public int SignatureLength => IsSm2 ? 64 : KeyBits / 8;

    private static readonly AlgorithmSuite Rsa2048 = new(
        "WOP-RSA2048-SHA256", SuiteFamily.Rsa, 2048,
        "SHA256withRSA", "AES-256-GCM", "RSA-2048-OAEP", "sha-256");

    private static readonly AlgorithmSuite Rsa3072 = new(
        "WOP-RSA3072-SHA256", SuiteFamily.Rsa, 3072,
        "SHA256withRSA", "AES-256-GCM", "RSA-3072-OAEP", "sha-256");

    private static readonly AlgorithmSuite Rsa4096 = new(
        "WOP-RSA4096-SHA256", SuiteFamily.Rsa, 4096,
        "SHA256withRSA", "AES-256-GCM", "RSA-4096-OAEP", "sha-256");

    private static readonly AlgorithmSuite Sm2 = new(
        "WOP-SM2-SM3", SuiteFamily.Sm2, 0,
        "SM3withSM2", "SM4-GCM", "SM2", "sm3");

    /// <summary>从 securityReq 解析算法套件（F1）。错误分类（spec §2.4）：
    /// 格式/前缀错误 → 解析类；算法不支持/跨族 → 支持类。两者对外语义均明确。</summary>
    public static AlgorithmSuite Parse(string securityReq)
    {
        var trimmed = (securityReq ?? "").Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            throw new WopException(WopErrorCode.SuiteParse, "securityReq 为空");
        }
        var parts = trimmed.Split('-');
        if (parts.Length != 3 || parts[0] != "WOP")
        {
            throw new WopException(WopErrorCode.SuiteParse,
                "securityReq 格式非法：应为 WOP-<密钥算法>-<摘要算法>，实际 " + trimmed);
        }
        return (parts[1], parts[2]) switch
        {
            ("RSA2048", "SHA256") => Rsa2048,
            ("RSA3072", "SHA256") => Rsa3072,
            ("RSA4096", "SHA256") => Rsa4096,
            ("SM2", "SM3") => Sm2,
            _ => throw new WopException(WopErrorCode.SuiteUnsupported,
                "不支持的算法组合：" + trimmed),
        };
    }
}
