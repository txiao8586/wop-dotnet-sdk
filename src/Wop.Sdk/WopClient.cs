using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Security;

namespace Wop.Sdk;

/// <summary>WOP 商户客户端（协议核心门面）：出向 BuildRequest（L0/L2 信封）与
/// 入向 VerifyResponse/VerifyCallback（F6 固定顺序校验）。
/// 请求方向：商户私钥加签、平台公钥包 DEK；响应/回调方向：平台公钥验签、商户私钥解包。
/// 线程安全（不可变）。</summary>
public sealed class WopClient
{
    private static readonly object DefaultLock = new();
    private static WopClient? _defaultClient;

    /// <summary>出向日志钩子（附录 I/I3 日志义务）：出向请求构造点收到一行含最终
    /// x-wop-request-id 值的日志（非敏感，豁免脱敏）。null → 缺省写 Console.Out
    /// （I3 INFO 级惯用通道：stderr 在容器采集器侧标 ERROR）。
    /// 测试/编排可整体替换。</summary>
    public static Action<string>? OutboundLogger { get; set; }

    private readonly string _appKey;
    private readonly AlgorithmSuite _suite;
    private readonly AsymmetricKeyMaterial _merchantPrivate;
    private readonly AsymmetricKeyMaterial _platformPublic;
    private readonly long _expiredSeconds;
    private readonly Func<long> _clock;
    private readonly Func<string> _nonceGen;
    private readonly SecureRandom _random;
    private readonly IWopTransport? _transport;

    internal WopClient(WopClientBuilder b, IWopTransport? transport)
    {
        _appKey = b.AppKeyValue;
        // Build() 已完成全部前置校验（原子装配，I6），此处不再防御
        _suite = b.SuiteValue!;
        _merchantPrivate = AsymmetricKeyMaterial.ParsePrivate(b.MerchantPrivateKeyValue!, _suite);
        _platformPublic = AsymmetricKeyMaterial.ParsePublic(b.PlatformPublicKeyValue!, _suite);
        _expiredSeconds = b.ExpiredSecondsValue;
        _clock = b.ClockValue;
        _nonceGen = b.NonceGenValue;
        _random = b.RandomValue;
        _transport = transport;
    }

    /// <summary>已装配的算法套件（只读）。</summary>
    public AlgorithmSuite Suite => _suite;

    /// <summary>创建构建器。</summary>
    public static WopClientBuilder Builder() => new();

    /// <summary>惰性：loadDefault → 传输发现 → 构造；缓存复用（K15）。</summary>
    public static WopClient DefaultClient()
    {
        lock (DefaultLock)
        {
            if (_defaultClient == null)
            {
                _defaultClient = FromConfig(WopConfigLoader.LoadDefault());
            }
            return _defaultClient;
        }
    }

    /// <summary>显式配置构造（不进默认实例缓存）。</summary>
    public static WopClient FromConfig(WopSdkConfig config)
    {
        if (config == null)
        {
            throw new WopException(WopErrorCode.Config, "config 为空");
        }
        var transport = config.Transport
                        ?? HttpClientTransport.Create(config.ServerRoot, config.HttpClient);
        return Builder()
            .AppKey(config.AppKey)
            .Suite(config.Suite)
            .MerchantPrivateKey(config.MerchantPrivateKey)
            .PlatformPublicKey(config.PlatformPublicKey)
            .ExpiredSeconds(config.ExpiredSeconds)
            .GatewayBaseUrl(config.ServerRoot)
            .Build(transport);
    }

    /// <summary>丢弃默认实例与初始化状态；轮换须先 <see cref="WopConfigLoader.ClearCache"/>（K26）。</summary>
    public static void ResetDefault()
    {
        lock (DefaultLock)
        {
            _defaultClient = null;
        }
    }

    // ==================== 出向 ====================

    /// <summary>构造请求草稿（headers + wireBody，零网络 IO；F9：CSPRNG nonce、毫秒时间戳、
    /// expiredSeconds 组装）。除 CSPRNG 值外同输入同输出（幂等）。
    /// D2：无 body（GET/空体）→ digest 头缺席；有 body 必产且必入 signedHeaders（I1）。
    /// L2 需要非空 body。</summary>
    public RequestDraft BuildRequest(string method, string path, byte[]? body, SecurityLevel level) =>
        BuildRequest(method, path, body, level, requestId: null);

    /// <summary>带商户请求标识的出向构造（wop-specs 附录 I）：<paramref name="requestId"/>
    /// 为不含个人数据的不透明关联标识，恒不入签（签名落盘后写入头）；null/空白 → 缺省生成
    /// UUID 去连字符（头恒存在），显式传值 trim 后原值上行；控制字符（trim 前原值扫描）与
    /// 超长（trim 后 UTF-8 字节 &gt; 128）构造即拒。</summary>
    public RequestDraft BuildRequest(string method, string path, byte[]? body, SecurityLevel level, string? requestId)
    {
        var upperMethod = (method ?? "").Trim().ToUpperInvariant();
        if (upperMethod.Length == 0)
        {
            throw new WopException(WopErrorCode.Config, "HTTP method 为空");
        }
        ConfigValidator.ValidateApiPath(path ?? "");
        // 附录 I/I2：requestId 构造即校验（fail-fast，不延迟到发送前）
        var resolvedRequestId = RequestId.Resolve(requestId);
        var hasBody = body is { Length: > 0 };
        if (level == SecurityLevel.L2 && !hasBody)
        {
            throw new WopException(WopErrorCode.Config, "L2 加密需要非空 body");
        }

        var headers = new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            [WopHeaders.AppKey] = _appKey,
            [WopHeaders.Timestamp] = _clock().ToString(System.Globalization.CultureInfo.InvariantCulture),
            [WopHeaders.Nonce] = _nonceGen(),
        };

        byte[]? wireBody = null;
        if (level == SecurityLevel.L2)
        {
            var (wire, encryptHeader) = SealEnvelope(body!);
            wireBody = wire;
            headers[WopHeaders.Encrypt] = encryptHeader;
        }
        else if (hasBody)
        {
            wireBody = body;
        }

        if (wireBody is { Length: > 0 })
        {
            headers[WopHeaders.ContentDigest] = ContentDigest.BuildHeaderValue(_suite, wireBody); // D2/D3/I1
        }

        var authString = WopSignProtocol.Version + "/" +
                         _expiredSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var canonical = CanonicalRequest.Build(authString, upperMethod, path!, "",
            CanonicalRequest.CanonicalHeaders(headers));
        // D14：出向签名 userId = 出向 x-wop-appkey 头值（= _appKey）
        var signature = WopCrypto.Sign(_suite, _merchantPrivate, Encoding.UTF8.GetBytes(canonical), Encoding.UTF8.GetBytes(_appKey), random: _random);
        var signedNames = headers.Keys.ToList();
        var signHeader = SignHeader.Build(_suite.SecurityReq, _expiredSeconds, signedNames, signature);

        var outHeaders = new Dictionary<string, string>(headers, StringComparer.Ordinal)
        {
            [WopHeaders.Sign] = signHeader,
        };
        // requestId 透传头（附录 I）：在签名落盘**之后**写入，保证不在 signedHeaders 冻结清单中；
        // 商户未传（含 trim 后为空）→ 缺省生成，最终头恒存在
        var effectiveRequestId = resolvedRequestId ?? RequestId.Generator();
        outHeaders[WopHeaders.RequestId] = effectiveRequestId;
        // 附录 I/I3 日志义务：出向构造点打印最终透传头值（非敏感，豁免脱敏），供网关 AccessLog 关联排查
        var logLine = WopHeaders.RequestId + "=" + effectiveRequestId + " " + upperMethod + " " + path;
        if (OutboundLogger != null)
        {
            OutboundLogger(logLine);
        }
        else
        {
            Console.Out.WriteLine(logLine);
        }
        return new RequestDraft(upperMethod, path!, outHeaders, wireBody);
    }

    /// <summary>L2 数字信封：CSPRNG CEK + IV（I4：IV 生成点唯一）→
    /// 套件报文策略全文加密 → JSON 信封 → 平台公钥包装 DEK。</summary>
    private (byte[] wireBody, string encryptHeader) SealEnvelope(byte[] plaintext)
    {
        var cek = new byte[_suite.CekLength];
        _random.NextBytes(cek);
        var iv = new byte[12];                       // GCM IV 12B（spec §3.3②）
        _random.NextBytes(iv);

        var sealedBytes = WopCrypto.SealMessage(_suite, plaintext, cek, iv);
        var wireBody = EncryptedEnvelope.Wrap(Codec.EncodeB64Url(sealedBytes));
        var dekPlain = Encoding.UTF8.GetBytes(DekPayload.Encode(_suite.MessageAlgorithm, cek, iv));
        var wrapped = WopCrypto.WrapDek(_suite, _platformPublic, dekPlain, random: _random);
        return (wireBody, EncryptHeader.BuildL2(wrapped));
    }

    // ==================== 入向（F6：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密） ====================

    /// <summary>校验网关响应。method/path 为商户原始请求的方法与路径
    /// （平台响应 canonical 复用请求 URI）。</summary>
    public VerifyResult VerifyResponse(string method, string path,
        IEnumerable<KeyValuePair<string, string>> headers, byte[]? body)
    {
        return Verify(method, path, headers, body);
    }

    /// <summary>校验平台回调：canonical URI 取回调 URL 的 path（不含 query），方法恒为 POST。</summary>
    public VerifyResult VerifyCallback(string callbackUrl,
        IEnumerable<KeyValuePair<string, string>> headers, byte[]? body)
    {
        string path;
        try
        {
            path = new Uri(callbackUrl, UriKind.Absolute).AbsolutePath;
        }
        catch (Exception)
        {
            return VerifyResult.Fail(new WopException(WopErrorCode.Protocol, "回调 URL 非法：" + callbackUrl));
        }
        if (string.IsNullOrEmpty(path) || path == "/")
        {
            return VerifyResult.Fail(new WopException(WopErrorCode.Protocol, "回调 URL 非法：" + callbackUrl));
        }
        return Verify("POST", path, headers, body);
    }

    /// <summary>一站式调用：BuildRequest → 内置 transport 发送 → 非 2xx 拦截 → VerifyResponse。</summary>
    public VerifyResult Execute(string method, string path, byte[]? body, SecurityLevel level) =>
        Execute(method, path, body, level, requestId: null);

    /// <summary>一站式调用（附录 I）：requestId 经请求级选项透传上行，语义同
    /// <see cref="BuildRequest(string,string,byte[],SecurityLevel,string?)"/>。</summary>
    public VerifyResult Execute(string method, string path, byte[]? body, SecurityLevel level, string? requestId)
    {
        if (_transport == null)
        {
            throw new WopException(WopErrorCode.Config, "未配置传输层，请使用 FromConfig 或 DefaultClient");
        }
        var draft = BuildRequest(method, path, body, level, requestId);
        var response = _transport.Send(draft);
        EnsureSuccessStatus(response);
        return Verify(draft.Method, draft.Path, response.Headers, response.Body);
    }

    /// <summary>一站式调用：BuildRequest → transport 发送 → VerifyResponse（F6）。</summary>
    public (VerifyResult Result, TransportResponse Response) Execute(IWopTransport transport,
        string method, string path, byte[]? body, SecurityLevel level) =>
        Execute(transport, method, path, body, level, requestId: null);

    /// <summary>一站式调用（附录 I）：requestId 经请求级选项透传上行，语义同
    /// <see cref="BuildRequest(string,string,byte[],SecurityLevel,string?)"/>。</summary>
    public (VerifyResult Result, TransportResponse Response) Execute(IWopTransport transport,
        string method, string path, byte[]? body, SecurityLevel level, string? requestId)
    {
        if (transport == null)
        {
            throw new WopException(WopErrorCode.Config, "transport 为空");
        }
        var draft = BuildRequest(method, path, body, level, requestId);
        var response = transport.Send(draft);
        EnsureSuccessStatus(response);
        return (Verify(draft.Method, draft.Path, response.Headers, response.Body), response);
    }

    /// <summary>非 2xx 不进验签，抛网关响应异常（§7.5）。</summary>
    private static void EnsureSuccessStatus(TransportResponse response)
    {
        if (response.StatusCode >= 200 && response.StatusCode < 300)
        {
            return;
        }
        throw new WopGatewayResponseException(response.StatusCode, response.Body);
    }

    /// <summary>验签统一入口：头名归一化（lowercase）后转 VerifyInbound；WopException → Fail。</summary>
    private VerifyResult Verify(string method, string path,
        IEnumerable<KeyValuePair<string, string>> headerPairs, byte[]? wireBody)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in headerPairs)
        {
            headers[name.ToLowerInvariant()] = value;
        }
        try
        {
            return VerifyInbound(method, path, headers, wireBody);
        }
        catch (WopException e)
        {
            return VerifyResult.Fail(e);
        }
    }

    /// <summary>入站校验主流程：签名头解析 → 套件一致性 → 结构前置校验（digest 缺席/入签）→ 验签 → L2 解密。
    /// 注：时间窗/nonce 重放防护由网关侧执行，本方法不校验。</summary>
    private VerifyResult VerifyInbound(string method, string path,
        Dictionary<string, string> headers, byte[]? wireBody)
    {
        // 0. 结构化签名头解析 + 套件一致性
        var parsed = SignHeader.Parse(GetHeader(headers, WopHeaders.Sign));
        if (parsed.SecurityReq != _suite.SecurityReq)
        {
            throw new WopException(WopErrorCode.Protocol,
                "响应套件 " + parsed.SecurityReq + " 与客户端配置 " + _suite.SecurityReq + " 不符");
        }

        // 1. 结构前置校验（公开协议知识，明确拒绝；先于验签）：
        //    D2 有 body 必传 digest、I1 digest 必入 signedHeaders
        var hasBody = wireBody is { Length: > 0 };
        if (hasBody)
        {
            if (string.IsNullOrEmpty(GetHeader(headers, WopHeaders.ContentDigest)))
            {
                throw new WopException(WopErrorCode.DigestMismatch, "有响应体但缺少 x-wop-content-digest");
            }
            if (!parsed.SignedHeaders.Contains(WopHeaders.ContentDigest))
            {
                throw new WopException(WopErrorCode.Protocol,
                    "x-wop-content-digest 未列入 signedHeaders（I1）");
            }
        }
        else if (!string.IsNullOrEmpty(GetHeader(headers, WopHeaders.ContentDigest)))
        {
            throw new WopException(WopErrorCode.Protocol, "无响应体不应携带 x-wop-content-digest");
        }

        // 2. 验签（I2：先验签后解密）：按 signedHeaders 从真实响应头重建 canonical
        var signedMap = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in parsed.SignedHeaders)
        {
            var value = GetHeader(headers, name);
            if (string.IsNullOrEmpty(value))
            {
                throw new WopException(WopErrorCode.Protocol, "已签名头 " + name + " 在响应中缺失");
            }
            signedMap[name] = value;
        }
        var canonical = CanonicalRequest.Build(parsed.AuthString, method, path, "",
            CanonicalRequest.CanonicalHeaders(signedMap));
        // D15：入向验签 userId 维持平台协议固定值（非 appKey；对齐 wop-go-sdk sm2PlatformUserID）
        WopCrypto.Verify(_suite, _platformPublic, Encoding.UTF8.GetBytes(canonical), parsed.Signature, Sm2PlatformDefaults.InboundUserId);

        // 3. digest 复核（D2/I5：格式 + 族耦合 + 值比对）
        if (hasBody)
        {
            ContentDigest.Validate(_suite, GetHeader(headers, WopHeaders.ContentDigest), wireBody!);
        }

        // 4-6. L2：DEK 解包 → alg 族比对（解包后、bulk 解密前，D8/I3）→ bulk 解密
        var encryptHeader = GetHeader(headers, WopHeaders.Encrypt);
        if (string.IsNullOrEmpty(encryptHeader))
        {
            return VerifyResult.Success(wireBody ?? Array.Empty<byte>());
        }
        var (_, dekB64Url) = EncryptHeader.Parse(encryptHeader);
        var payloadPlain = WopCrypto.UnwrapDek(_suite, _merchantPrivate, dekB64Url);   // I7：模糊
        DekPayload payload;
        try
        {
            payload = DekPayload.Parse(Encoding.UTF8.GetString(payloadPlain));
        }
        catch (WopException)
        {
            // DEK 载荷结构在解包之后才可见，属密钥参与层；除 alg 族不符（D8 明确，
            // 由下一判给出）外一律归入解密类模糊（I7 保守默认，interop 合同 n13）
            throw WopException.Fuzzy(WopErrorCode.DecryptFailed);
        }
        if (!payload.MatchesSuite(_suite))
        {
            throw new WopException(WopErrorCode.AlgMismatch,
                "dek alg " + payload.Alg + " 与套件 " + _suite.SecurityReq + " 族不符（期望 " +
                _suite.MessageAlgorithm + "）");
        }
        var cipherB64Url = EncryptedEnvelope.Extract(wireBody!);
        var ciphertext = Codec.DecodeB64Url(cipherB64Url);
        var plaintext = WopCrypto.OpenMessage(_suite, ciphertext, payload.Key, payload.Iv); // I7：模糊
        return VerifyResult.Success(plaintext);
    }

    /// <summary>取头（缺失返回空串）。</summary>
    private static string GetHeader(Dictionary<string, string> headers, string name)
    {
        return headers.TryGetValue(name, out var v) ? v : "";
    }
}

/// <summary>WopClient 构建器（spec §2 概念 API 的 .NET 惯用映射）。
/// 密钥入参为字符串（PEM 或 Base64 单行，D12）；Build 时原子装配（I6）。</summary>
public sealed class WopClientBuilder
{
    internal string AppKeyValue { get; private set; } = "";
    internal AlgorithmSuite? SuiteValue { get; private set; }
    internal string? MerchantPrivateKeyValue { get; private set; }
    internal string? PlatformPublicKeyValue { get; private set; }
    internal long ExpiredSecondsValue { get; private set; } = WopSignProtocol.ExpiredSecondsDefault;
    internal Func<long> ClockValue { get; private set; } = DefaultClock;
    internal Func<string> NonceGenValue { get; private set; } = DefaultNonce;
    internal SecureRandom RandomValue { get; private set; } = new();
    internal string? GatewayBaseUrlValue { get; private set; }

    /// <summary>默认时钟：Unix 毫秒。</summary>
    private static long DefaultClock() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>默认 nonce：CSPRNG 16 字节小写 hex。</summary>
    private static string DefaultNonce()
    {
        var bytes = new byte[16];
        new SecureRandom().NextBytes(bytes);
        return Codec.LowerHex(bytes);
    }

    /// <summary>商户 appKey。</summary>
    public WopClientBuilder AppKey(string appKey)
    {
        AppKeyValue = appKey;
        return this;
    }

    /// <summary>算法套件（securityReq，如 WOP-RSA3072-SHA256 / WOP-SM2-SM3）。</summary>
    public WopClientBuilder Suite(string securityReq)
    {
        SuiteValue = AlgorithmSuite.Parse(securityReq);
        return this;
    }

    /// <summary>商户私钥（PEM 或 Base64 单行）：请求加签 / 响应 DEK 解包。
    /// 解析延迟到 Build（I6：套件 + 双钥原子装配）。</summary>
    public WopClientBuilder MerchantPrivateKey(string material)
    {
        MerchantPrivateKeyValue = material;
        return this;
    }

    /// <summary>平台公钥（PEM 或 Base64 单行）：响应/回调验签 / DEK 包装。</summary>
    public WopClientBuilder PlatformPublicKey(string material)
    {
        PlatformPublicKeyValue = material;
        return this;
    }

    /// <summary>网关基地址（可选；仅 Execute 路径消费）。</summary>
    public WopClientBuilder GatewayBaseUrl(string baseUrl)
    {
        GatewayBaseUrlValue = baseUrl;
        return this;
    }

    /// <summary>签名有效时长（秒，默认 1800，上限 86400）。</summary>
    public WopClientBuilder ExpiredSeconds(long seconds)
    {
        ExpiredSecondsValue = seconds;
        return this;
    }

    /// <summary>固定时钟（联调/测试确定性钩子）。</summary>
    internal WopClientBuilder WithClock(Func<long> clock)
    {
        ClockValue = clock;
        return this;
    }

    /// <summary>固定 nonce 生成器（联调/测试确定性钩子）。</summary>
    internal WopClientBuilder WithNonce(Func<string> nonceGen)
    {
        NonceGenValue = nonceGen;
        return this;
    }

    /// <summary>固定随机源（联调/测试确定性钩子）：注入后随机流按合同顺序消费
    /// [CEK][12B IV][OAEP seed / SM2 k…]（wop-specs/interop/v1）。</summary>
    internal WopClientBuilder WithRandom(SecureRandom random)
    {
        RandomValue = random;
        return this;
    }

    /// <summary>构建客户端：套件原子装配 + 密钥格式/位数校验（错误均明确）。</summary>
    public WopClient Build() => BuildInternal(null);

    /// <summary>构建客户端并绑定传输（配置层 FromConfig 使用）。</summary>
    public WopClient Build(IWopTransport transport) => BuildInternal(transport);

    private WopClient BuildInternal(IWopTransport? transport)
    {
        if (string.IsNullOrWhiteSpace(AppKeyValue))
        {
            throw new WopException(WopErrorCode.Config, "appKey 为空");
        }
        if (SuiteValue == null)
        {
            throw new WopException(WopErrorCode.SuiteParse, "suite 未配置");
        }
        if (string.IsNullOrEmpty(MerchantPrivateKeyValue))
        {
            throw new WopException(WopErrorCode.Config, "商户私钥未配置");
        }
        if (string.IsNullOrEmpty(PlatformPublicKeyValue))
        {
            throw new WopException(WopErrorCode.Config, "平台公钥未配置");
        }
        if (ExpiredSecondsValue <= 0 || ExpiredSecondsValue > WopSignProtocol.ExpiredSecondsMax)
        {
            throw new WopException(WopErrorCode.Protocol,
                "expiredSeconds 超出允许范围 (0, " + WopSignProtocol.ExpiredSecondsMax + "]");
        }
        return new WopClient(this, transport);
    }
}
