using Wop.Sdk;
using Xunit;

public class AlgorithmSuiteTests
{
    [Theory]
    [InlineData("WOP-RSA2048-SHA256", SuiteFamily.Rsa, 2048, "SHA256withRSA", "AES-256-GCM", "RSA-2048-OAEP", "sha-256")]
    [InlineData("WOP-RSA3072-SHA256", SuiteFamily.Rsa, 3072, "SHA256withRSA", "AES-256-GCM", "RSA-3072-OAEP", "sha-256")]
    [InlineData("WOP-RSA4096-SHA256", SuiteFamily.Rsa, 4096, "SHA256withRSA", "AES-256-GCM", "RSA-4096-OAEP", "sha-256")]
    [InlineData("WOP-SM2-SM3", SuiteFamily.Sm2, 0, "SM3withSM2", "SM4-GCM", "SM2", "sm3")]
    public void Parse_合法套件推导四维算法(string securityReq, SuiteFamily family, int keyBits,
        string sign, string message, string keyWrap, string digestTag)
    {
        var s = AlgorithmSuite.Parse(securityReq);
        Assert.Equal(securityReq, s.SecurityReq);
        Assert.Equal(family, s.Family);
        Assert.Equal(keyBits, s.KeyBits);
        Assert.Equal(sign, s.SignAlgorithm);
        Assert.Equal(message, s.MessageAlgorithm);
        Assert.Equal(keyWrap, s.KeyWrapAlgorithm);
        Assert.Equal(digestTag, s.DigestTag);
        Assert.Equal(family == SuiteFamily.Sm2, s.IsSm2);
    }

    [Theory]
    [InlineData("WOP-RSA3072-SM3", WopErrorCode.SuiteUnsupported)]   // 跨族：国际密钥+国密摘要（I5）
    [InlineData("WOP-SM2-SHA256", WopErrorCode.SuiteUnsupported)]    // 跨族：国密密钥+国际摘要（I5）
    [InlineData("WOP-RSA1024-SHA256", WopErrorCode.SuiteUnsupported)] // 未支持密钥长度
    [InlineData("WOP-SM4-SM3", WopErrorCode.SuiteUnsupported)]       // 未支持密钥算法
    [InlineData("WOP-RSA3072-SM4", WopErrorCode.SuiteUnsupported)]   // 未支持摘要算法
    public void Parse_非法组合支持类拒绝(string securityReq, WopErrorCode code)
    {
        var ex = Assert.Throws<WopException>(() => AlgorithmSuite.Parse(securityReq));
        Assert.Equal(code, ex.ErrorCode);
    }

    [Theory]
    [InlineData("", WopErrorCode.SuiteParse)]
    [InlineData("   ", WopErrorCode.SuiteParse)]
    [InlineData("RSA3072-SHA256", WopErrorCode.SuiteParse)]          // 缺前缀
    [InlineData("XXX-RSA3072-SHA256", WopErrorCode.SuiteParse)]      // 前缀非 WOP
    [InlineData("WOP-RSA3072", WopErrorCode.SuiteParse)]             // 段数不足
    [InlineData("WOP-RSA3072-SHA256-EXTRA", WopErrorCode.SuiteParse)] // 段数过多
    [InlineData("WOP--", WopErrorCode.SuiteUnsupported)]     // 空段 = 未知算法（对齐 Go 语义）
    [InlineData("WOP RSA3072 SHA256", WopErrorCode.SuiteParse)]   // 空格分隔非三段式
    public void Parse_格式错误解析类拒绝(string securityReq, WopErrorCode code)
    {
        var ex = Assert.Throws<WopException>(() => AlgorithmSuite.Parse(securityReq));
        Assert.Equal(code, ex.ErrorCode);
    }

    [Theory]
    [InlineData(" WOP-RSA3072-SHA256 ", 32, 384)]   // trim 容忍（对齐 Go ParseSuite）
    [InlineData("WOP-RSA3072-SHA256", 32, 384)]
    [InlineData("WOP-RSA4096-SHA256", 32, 512)]
    [InlineData("WOP-SM2-SM3", 16, 64)]
    public void 套件推导CEK与签名定长(string securityReq, int cekLen, int sigLen)
    {
        var s = AlgorithmSuite.Parse(securityReq);
        Assert.Equal(cekLen, s.CekLength);
        Assert.Equal(sigLen, s.SignatureLength);
    }
}
