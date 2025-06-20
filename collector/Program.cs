using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using AiTrafficInterceptor.Collector;
using Serilog;
using Serilog.Events;
using LogEventLevel = Serilog.Events.LogEventLevel;
using CollectorLogEvent = AiTrafficInterceptor.Collector.LogEvent;

// --- Serilog Configuration ---
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Information)
    .WriteTo.File("logs/aiti-collector-.log",
        rollingInterval: RollingInterval.Day,
        rollOnFileSizeLimit: true,
        fileSizeLimitBytes: 10 * 1024 * 1024, // 10 MB
        retainedFileCountLimit: 7)
    .CreateLogger();

Log.Information("AI Traffic Collector starting...");

bool verbose = args.Contains("--verbose", StringComparer.OrdinalIgnoreCase);
if (verbose)
{
    Log.Information("[Verbose mode ON] Raw JSON and decoded payloads will be printed.");
}

Log.Information("Waiting for connection on \\\\.\\pipe\\{PipeName}", "ai-hook");

const string pipeName = "ai-hook";
var analysisEngine = new AnalysisEngine();

while (true) // Loop to allow reconnects
{
    try
    {
        await using var server = new NamedPipeServerStream(pipeName, PipeDirection.In, 10, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await server.WaitForConnectionAsync();

        Log.Information("Client connected.");

        using var reader = new StreamReader(server, Encoding.UTF8);
        while (server.IsConnected)
        {
            string? line = await reader.ReadLineAsync();
            if (line == null) // Pipe was closed
            {
                break;
            }

            try
            {
                var logEvent = JsonSerializer.Deserialize<CollectorLogEvent>(line);
                if (logEvent != null)
                {
                    Log.Information("[{Timestamp:s}] PID:{ProcessId} API:{Api} URL:{Url}", 
                        logEvent.Timestamp, logEvent.ProcessId, logEvent.Api, logEvent.Url);
                        
                    if (verbose)
                    {
                        Log.Debug("  Raw JSON: {RawJson}", line);
                        var decoded = logEvent.DecodedData;
                        if (decoded != null && decoded.Length > 0)
                        {
                            Log.Debug("  Decoded payload (first 500 bytes): {Payload}", Encoding.UTF8.GetString(decoded.AsSpan(0, Math.Min(decoded.Length, 500))));
                        }
                    }
                    
                    var analysisResult = analysisEngine.Analyze(logEvent);
                    if (analysisResult.HasFindings)
                    {
                        foreach (var finding in analysisResult.Findings)
                        {
                            Log.Warning("  [!] {Finding}", finding);
                        }
                    }
                }
            }
            catch (JsonException ex)
            {
                Log.Error(ex, "Error deserializing JSON: {Message}", ex.Message);
            }
        }
    }
    catch (Exception ex)
    {
        Log.Error(ex, "An error occurred: {Message}", ex.Message);
    }

    Log.Information("Client disconnected. Waiting for new connection...");
    await Task.Delay(1000); // Prevent tight loop on error
}
