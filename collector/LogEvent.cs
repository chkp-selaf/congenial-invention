using System.Text.Json.Serialization;

namespace AiTrafficInterceptor.Collector;

public class LogEvent
{
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }

    [JsonPropertyName("processId")]
    public uint ProcessId { get; set; }

    [JsonPropertyName("threadId")]
    public uint ThreadId { get; set; }

    [JsonPropertyName("api")]
    public string Api { get; set; } = "";

    [JsonPropertyName("url")]
    public string Url { get; set; } = "";

    [JsonPropertyName("data_b64")]
    public string DataB64 { get; set; } = "";

    // Helper property to get the decoded data
    public byte[]? DecodedData => !string.IsNullOrEmpty(DataB64) ? Convert.FromBase64String(DataB64) : null;
}
