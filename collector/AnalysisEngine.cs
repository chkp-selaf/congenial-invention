using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace AiTrafficInterceptor.Collector;

public class AnalysisEngine
{
    // Basic regex for demonstration. A real implementation would be more robust.
    private static readonly List<(string Name, Regex Pattern)> PiiPatterns = new()
    {
        ("Email", new Regex(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", RegexOptions.Compiled)),
        ("API Key", new Regex(@"(sk-[a-zA-Z0-9]{20,})", RegexOptions.Compiled)), // Example for OpenAI-like keys
        ("IPv4", new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", RegexOptions.Compiled))
    };

    private static readonly List<(string Name, Regex Pattern)> PromptInjectionPatterns = new()
    {
        ("Ignore Instructions", new Regex(@"ignore.*previous.*instructions", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        ("Reveal Instructions", new Regex(@"reveal.*instructions|what are your instructions", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
    };

    public AnalysisResult Analyze(LogEvent logEvent)
    {
        var result = new AnalysisResult();
        if (logEvent.DecodedData == null || logEvent.DecodedData.Length == 0)
        {
            return result;
        }

        string content = Encoding.UTF8.GetString(logEvent.DecodedData);

        // Check for PII
        foreach (var (name, pattern) in PiiPatterns)
        {
            if (pattern.IsMatch(content))
            {
                result.HasPii = true;
                result.Findings.Add($"Potential PII Detected: {name}");
            }
        }

        // Check for Prompt Injection
        foreach (var (name, pattern) in PromptInjectionPatterns)
        {
            if (pattern.IsMatch(content))
            {
                result.HasPromptInjection = true;
                result.Findings.Add($"Potential Prompt Injection Detected: {name}");
            }
        }

        return result;
    }
}
