using System.Collections.Generic;

namespace AiTrafficInterceptor.Collector;

public class AnalysisResult
{
    public bool HasPii { get; set; }
    public bool HasPromptInjection { get; set; }
    public List<string> Findings { get; } = new List<string>();

    public bool HasFindings => HasPii || HasPromptInjection;
}
