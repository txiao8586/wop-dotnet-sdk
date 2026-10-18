using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Wop.Sdk;

/// <summary>配置 JSON 解析（K8/K21）：Utf8JsonReader 预扫重复键后 Deserialize + §3.4 校验。</summary>
internal static class ConfigJsonParser
{
    private static readonly JsonSerializerOptions DeserializeOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        NumberHandling = JsonNumberHandling.Strict,
        AllowTrailingCommas = false,
    };

    /// <summary>解析 UTF-8 JSON 文本为不可变配置快照。</summary>
    internal static WopSdkConfig Parse(string json)
    {
        if (json == null)
        {
            throw Config("配置文件 JSON 解析失败: 空内容");
        }

        var trimmed = StripBom(json.Trim());
        if (trimmed.Length == 0)
        {
            throw Config("配置文件 JSON 解析失败: 空文件");
        }

        var utf8 = Encoding.UTF8.GetBytes(trimmed);
        try
        {
            DuplicateKeyPrescanner.Scan(utf8);
        }
        catch (JsonException e)
        {
            // 预扫同样可能遇畸形 JSON（缺逗号等）——与 Deserialize 同口径归一为 configuration
            throw Config("配置文件 JSON 解析失败: " + e.Message);
        }

        WopSdkConfigJson dto;
        try
        {
            dto = JsonSerializer.Deserialize<WopSdkConfigJson>(utf8, DeserializeOptions)
                  ?? throw Config("配置文件 JSON 解析失败: 根节点非对象");
        }
        catch (JsonException e)
        {
            throw Config("配置文件 JSON 解析失败: " + e.Message);
        }

        var http = dto.HttpClient == null
            ? HttpClientSettings.Defaults
            : new HttpClientSettings(
                dto.HttpClient.ConnectTimeout ?? HttpClientSettings.DefaultConnectTimeout,
                dto.HttpClient.ReadTimeout ?? HttpClientSettings.DefaultReadTimeout,
                dto.HttpClient.MaxRetryCount ?? HttpClientSettings.DefaultMaxRetryCount);

        var raw = new WopSdkConfig(
            dto.AppKey ?? "",
            dto.Suite ?? "",
            dto.MerchantPrivateKey ?? "",
            dto.PlatformPublicKey ?? "",
            dto.ServerRoot ?? "",
            dto.BackupServerRoots ?? new List<string>(),
            dto.ExpiredSeconds ?? WopSignProtocol.ExpiredSecondsDefault,
            http,
            null);

        return ConfigValidator.ValidateAndNormalize(raw);
    }

    /// <summary>剥离 UTF-8 BOM（§4.3 容忍并剥离）。</summary>
    private static string StripBom(string text) =>
        text.StartsWith("\uFEFF", StringComparison.Ordinal) ? text.Substring(1) : text;

    /// <summary>统一构造 configuration 异常（对外文案「配置…」，§3.4）。</summary>
    private static WopException Config(string message) =>
        new(WopErrorCode.Config, message);

    /// <summary>Utf8JsonReader 预扫对象键，遇重复键即 fail-fast（§4.4 K21）。</summary>
    private static class DuplicateKeyPrescanner
    {
        /// <summary>Utf8JsonReader 预扫入口：重复键即 configuration（K21，§4.4）。</summary>
    internal static void Scan(ReadOnlySpan<byte> utf8Json)
        {
            var reader = new Utf8JsonReader(utf8Json, new JsonReaderOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
            });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                throw Config("配置文件 JSON 解析失败: 根节点须为对象");
            }
            ScanObject(ref reader, nestedHttpClient: false);
        }

        /// <summary>对象帧扫描：记录已见键；httpClient 外再嵌对象即 configuration（§4.4）。</summary>
    private static void ScanObject(ref Utf8JsonReader reader, bool nestedHttpClient)
        {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    return;
                }
                // Utf8JsonReader 保证对象帧内非 EndObject 处必为 PropertyName（缺逗号等在
                // Read() 即抛 JsonException），故不再重复判 token 类型
                var key = reader.GetString() ?? "";
                if (!keys.Add(key))
                {
                    throw Config("配置字段 " + key + " 重复: " + key);
                }

                reader.Read(); // 值 token；截断/畸形由 Read() 抛 JsonException 统一拒绝

                if (!nestedHttpClient && key == "httpClient")
                {
                    if (reader.TokenType != JsonTokenType.StartObject)
                    {
                        throw Config("配置字段 httpClient 类型非法: 期望对象");
                    }
                    ScanObject(ref reader, nestedHttpClient: true);
                }
                else if (nestedHttpClient && reader.TokenType == JsonTokenType.StartObject)
                {
                    throw Config("配置字段 httpClient 类型非法: 不支持更深嵌套");
                }
                else
                {
                    SkipValue(ref reader);
                }
            }
        }

        /// <summary>跳过任意 JSON 值（未知字段忽略，§4.4）。</summary>
    private static void SkipValue(ref Utf8JsonReader reader)
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.String:
                case JsonTokenType.Number:
                case JsonTokenType.True:
                case JsonTokenType.False:
                case JsonTokenType.Null:
                    return;
                case JsonTokenType.StartObject:
                    // 同上：对象帧内 token 位置由 tokenizer 保证，截断由 Read() 抛 JsonException
                    while (reader.Read())
                    {
                        if (reader.TokenType == JsonTokenType.EndObject)
                        {
                            return;
                        }
                        reader.Read();
                        SkipValue(ref reader);
                    }
                    break;
                case JsonTokenType.StartArray:
                    while (reader.Read())
                    {
                        if (reader.TokenType == JsonTokenType.EndArray)
                        {
                            return;
                        }
                        SkipValue(ref reader);
                    }
                    break;
            }
        }
    }

    private sealed class WopSdkConfigJson
    {
        [JsonPropertyName("appKey")]
        public string? AppKey { get; set; }

        [JsonPropertyName("suite")]
        public string? Suite { get; set; }

        [JsonPropertyName("merchantPrivateKey")]
        public string? MerchantPrivateKey { get; set; }

        [JsonPropertyName("platformPublicKey")]
        public string? PlatformPublicKey { get; set; }

        [JsonPropertyName("serverRoot")]
        public string? ServerRoot { get; set; }

        [JsonPropertyName("backupServerRoots")]
        public List<string>? BackupServerRoots { get; set; }

        [JsonPropertyName("expiredSeconds")]
        public long? ExpiredSeconds { get; set; }

        [JsonPropertyName("httpClient")]
        public HttpClientSettingsJson? HttpClient { get; set; }
    }

    private sealed class HttpClientSettingsJson
    {
        [JsonPropertyName("connectTimeout")]
        public int? ConnectTimeout { get; set; }

        [JsonPropertyName("readTimeout")]
        public int? ReadTimeout { get; set; }

        [JsonPropertyName("maxRetryCount")]
        public int? MaxRetryCount { get; set; }
    }
}
