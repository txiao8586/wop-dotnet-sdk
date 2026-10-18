using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Wop.Sdk.Tests;

// 黄金向量钉版拉取（对齐 java-sdk 构建期模式）：真源 wop-platform/wop-specs，
// 副本不落库，模块加载即按 Ref+sha256 拉取校验，mismatch 即抛（fail-closed）。
// 升级流程见 CONTRIBUTING：先合 wop-specs PR，再同步 Ref 与 Files 钉版三件套。
internal static class SpecsPinnedFetch
{
    private const string Ref = "a1f7feb5b4af5c9052149e2adfd2063caa102677";

    private static readonly (string Src, string Sha256)[] Files =
    [
        ("crypto/crypto-vectors.json", "c7dd65740a1da9a5cfb804bca0c8b1bd7d4ab967adeb075297677a4bef148736"),
        ("interop/v1/interop-cases.json", "c920ca1a93ccb3899a659f59fed6ec4652cf9e1b3b58bbdac23c45ac3ed2353e"),
    ];

    [ModuleInitializer]
    internal static void Fetch()
    {
        var dir = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, "fixtures");
        using var http = new HttpClient();
        foreach (var (src, sha) in Files)
        {
            var data = http.GetByteArrayAsync(
                $"https://raw.githubusercontent.com/wop-platform/wop-specs/{Ref}/{src}").GetAwaiter().GetResult();
            var digest = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
            if (digest != sha)
            {
                throw new InvalidOperationException(
                    $"wop-specs {src} sha256 mismatch：期望 {sha} 实得 {digest}；向量升级须先合 wop-specs PR 再同步钉版");
            }
            Directory.CreateDirectory(dir);
            File.WriteAllBytes(Path.Combine(dir, Path.GetFileName(src)), data);
        }
    }
}
