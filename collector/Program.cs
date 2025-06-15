using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using AiTrafficInterceptor.Collector;

Console.WriteLine("AI Traffic Collector starting...");

bool verbose = args.Contains("--verbose", StringComparer.OrdinalIgnoreCase);
if (verbose)
{
    Console.WriteLine("[Verbose mode ON] Raw JSON and decoded payloads will be printed.");
}

Console.WriteLine("Waiting for connection on \\.[2m\\pipe\\ai-hook[0m");

const string pipeName = "ai-hook";
var analysisEngine = new AnalysisEngine();

while (true) // Loop to allow reconnects
{
    try
    {
        await using var server = new NamedPipeServerStream(pipeName, PipeDirection.In, 10, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await server.WaitForConnectionAsync();

        Console.WriteLine("Client connected.");

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
                var logEvent = JsonSerializer.Deserialize<LogEvent>(line);
                if (logEvent != null)
                {
                    Console.WriteLine($"[{logEvent.Timestamp:s}] PID:{logEvent.ProcessId} API:{logEvent.Api} URL:{logEvent.Url}");
                    if (verbose)
                    {
                        Console.WriteLine($"  Raw JSON: {line}");
                        var decoded = logEvent.DecodedData;
                        if (decoded != null && decoded.Length > 0)
                        {
                            Console.WriteLine($"  Decoded payload (first 500 bytes): {Encoding.UTF8.GetString(decoded.AsSpan(0, Math.Min(decoded.Length, 500)))}");
                        }
                    }
                    
                    var analysisResult = analysisEngine.Analyze(logEvent);
                    if (analysisResult.HasFindings)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        foreach (var finding in analysisResult.Findings)
                        {
                            Console.WriteLine($"  [!] {finding}");
                        }
                        Console.ResetColor();
                    }

                    // For verbose output of all data, uncomment below:
                    // var decoded = logEvent.DecodedData;
                    // if (decoded != null && decoded.Length > 0) {
                    //     Console.WriteLine($"  Data: {Encoding.UTF8.GetString(decoded)}");
                    // }
                }
            }
            catch (JsonException ex)
            {
                Console.WriteLine($"Error deserializing JSON: {ex.Message}");
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"An error occurred: {ex.Message}");
    }

    Console.WriteLine("Client disconnected. Waiting for new connection...");
    await Task.Delay(1000); // Prevent tight loop on error
}
