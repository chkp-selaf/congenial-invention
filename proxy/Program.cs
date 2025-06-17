using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.IO.Pipes;
using System.Net;

// Simple self-contained reverse proxy for OpenAI-style JSON traffic.
//  * Listens on http://127.0.0.1:8080
//  * Forwards to the endpoint in AITI_UPSTREAM (default https://api.openai.com)
//  * Streams each request body to the collector via named pipe as LogEvent

internal class Program
{
    private const string PipeName = "ai-hook";

    public static async Task Main()
    {
        string upstreamBase = Environment.GetEnvironmentVariable("AITI_UPSTREAM") ?? "https://api.openai.com";
        Console.WriteLine($"[Proxy] Upstream base URL: {upstreamBase}");

        var http = new HttpListener();
        http.Prefixes.Add("http://127.0.0.1:8080/");
        http.Start();
        Console.WriteLine("[Proxy] Listening on http://127.0.0.1:8080 ...");

        using HttpClient client = new();

        while (true)
        {
            var ctx = await http.GetContextAsync();
            _ = HandleRequestAsync(ctx, client, upstreamBase);
        }
    }

    private static async Task HandleRequestAsync(HttpListenerContext ctx, HttpClient client, string upstreamBase)
    {
        try
        {
            var req = ctx.Request;
            using var ms = new MemoryStream();
            if (req.HasEntityBody)
            {
                await req.InputStream.CopyToAsync(ms);
            }
            byte[] bodyBytes = ms.ToArray();
            string bodyString = Encoding.UTF8.GetString(bodyBytes);

            var fwd = new HttpRequestMessage(new HttpMethod(req.HttpMethod), upstreamBase + req.RawUrl)
            {
                Content = new StringContent(bodyString, Encoding.UTF8, "application/json")
            };
            foreach (string header in req.Headers.AllKeys!)
            {
                if (header.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
                fwd.Headers.TryAddWithoutValidation(header, req.Headers[header]);
            }

            HttpResponseMessage resp = await client.SendAsync(fwd, HttpCompletionOption.ResponseHeadersRead);
            string respBody = await resp.Content.ReadAsStringAsync();

            await SendLogAsync(req.RawUrl ?? string.Empty, bodyString);

            byte[] respBytes = Encoding.UTF8.GetBytes(respBody);
            ctx.Response.StatusCode = (int)resp.StatusCode;
            foreach (var h in resp.Headers)
            {
                ctx.Response.Headers[h.Key] = string.Join(",", h.Value);
            }
            ctx.Response.Headers["Content-Type"] = "application/json";
            ctx.Response.ContentLength64 = respBytes.Length;
            await ctx.Response.OutputStream.WriteAsync(respBytes, 0, respBytes.Length);
            ctx.Response.Close();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Proxy] Error: {ex.Message}");
            try { ctx.Response.StatusCode = 500; ctx.Response.Close(); } catch { }
        }
    }

    private static NamedPipeClientStream? _pipe;
    private static void EnsurePipe()
    {
        if (_pipe != null && _pipe.IsConnected) return;
        _pipe?.Dispose();
        _pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.Out, PipeOptions.Asynchronous);
        try { _pipe.Connect(500); }
        catch { }
    }

    private static async Task SendLogAsync(string url, string body)
    {
        EnsurePipe();
        if (_pipe == null || !_pipe.IsConnected) return;

        var ev = new LogEvent
        {
            Timestamp = DateTime.UtcNow,
            ProcessId = (uint)Environment.ProcessId,
            ThreadId = 0,
            Api = "OpenAIProxy",
            Url = url,
            DataB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(body))
        };

        string json = JsonSerializer.Serialize(ev);
        byte[] bytes = Encoding.UTF8.GetBytes(json + "\n");
        await _pipe.WriteAsync(bytes, 0, bytes.Length);
        await _pipe.FlushAsync();
    }
}

internal record LogEvent
{
    [JsonPropertyName("timestamp")] public DateTime Timestamp { get; init; }
    [JsonPropertyName("processId")] public uint ProcessId { get; init; }
    [JsonPropertyName("threadId")] public uint ThreadId { get; init; }
    [JsonPropertyName("api")] public string Api { get; init; } = "";
    [JsonPropertyName("url")] public string Url { get; init; } = "";
    [JsonPropertyName("data_b64")] public string DataB64 { get; init; } = "";
} 