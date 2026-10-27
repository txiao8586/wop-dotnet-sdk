namespace Wop.Sdk;

/// <summary>ISV 子商户身份头 x-wop-sub-mch-id（ISV D-13）。
/// 值 = 子商户 plf_co_id；存在即入签，缺席 = 应用自身身份（AC-20）。</summary>
internal static class SubMchId
{
    /// <summary>校验并归一化：可打印 ASCII（0x20..0x7E，trim 前扫描防头注入）、
    /// trim 后为空 → null（头缺席）、无内部空格、长度 ≤ 128（字符数）。
    /// 返回 trim 后上行值。</summary>
    internal static string? Resolve(string? raw)
    {
        if (raw == null || raw.Length == 0)
        {
            return null;
        }
        foreach (var ch in raw)
        {
            if (ch < 0x20 || ch > 0x7E)
            {
                throw new WopException(WopErrorCode.Config,
                    "subMchId 须为可打印 ASCII（防头注入/签名歧义）: " + (int)ch);
            }
        }
        var trimmed = raw.Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }
        // 网关 canonical 的 trimall 会折叠内部空白，而身份查询只做 trim——
        // 内部空白破坏签名与身份一一对应
        if (trimmed.IndexOf(' ') >= 0)
        {
            throw new WopException(WopErrorCode.Config, "subMchId 不能包含内部空白");
        }
        if (trimmed.Length > 128)
        {
            throw new WopException(WopErrorCode.Config,
                "subMchId 长度不能超过 128（实际 " + trimmed.Length + "）");
        }
        return trimmed;
    }
}
