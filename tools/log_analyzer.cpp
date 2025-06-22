#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <iomanip>
#include <regex>

struct LogEntry {
    std::wstring timestamp;
    std::wstring level;
    DWORD pid;
    DWORD tid;
    std::wstring component;
    std::wstring message;
};

class LogAnalyzer {
private:
    std::vector<LogEntry> entries;
    std::map<std::wstring, int> levelCounts;
    std::map<std::wstring, int> componentCounts;
    std::map<DWORD, int> pidCounts;
    
    bool ParseLogLine(const std::wstring& line, LogEntry& entry) {
        // Expected format: [2024-01-01 12:00:00.123] [LEVEL] [PID:1234] [TID:5678] [Component] Message
        std::wregex pattern(L"\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3})\\] \\[([A-Z]+)\\] \\[PID:(\\d+)\\] \\[TID:(\\d+)\\] \\[([^\\]]+)\\] (.+)");
        std::wsmatch match;
        
        if (std::regex_match(line, match, pattern)) {
            entry.timestamp = match[1];
            entry.level = match[2];
            entry.pid = std::stoul(match[3]);
            entry.tid = std::stoul(match[4]);
            entry.component = match[5];
            entry.message = match[6];
            return true;
        }
        return false;
    }
    
public:
    void LoadLogFile(const std::wstring& filepath) {
        std::wifstream file(filepath);
        if (!file.is_open()) {
            std::wcerr << L"Failed to open log file: " << filepath << std::endl;
            return;
        }
        
        std::wstring line;
        int lineNum = 0;
        int parsedCount = 0;
        
        while (std::getline(file, line)) {
            lineNum++;
            LogEntry entry;
            if (ParseLogLine(line, entry)) {
                entries.push_back(entry);
                levelCounts[entry.level]++;
                componentCounts[entry.component]++;
                pidCounts[entry.pid]++;
                parsedCount++;
            }
        }
        
        std::wcout << L"Loaded " << parsedCount << L" log entries from " << lineNum << L" lines" << std::endl;
    }
    
    void PrintSummary() {
        std::wcout << L"\n=== LOG ANALYSIS SUMMARY ===" << std::endl;
        std::wcout << L"Total entries: " << entries.size() << std::endl;
        
        // Level distribution
        std::wcout << L"\nLog Level Distribution:" << std::endl;
        for (const auto& [level, count] : levelCounts) {
            std::wcout << L"  " << std::setw(10) << level << L": " << count << std::endl;
        }
        
        // Component distribution
        std::wcout << L"\nComponent Distribution:" << std::endl;
        for (const auto& [component, count] : componentCounts) {
            std::wcout << L"  " << std::setw(15) << component << L": " << count << std::endl;
        }
        
        // Process distribution
        std::wcout << L"\nProcess Distribution:" << std::endl;
        for (const auto& [pid, count] : pidCounts) {
            std::wcout << L"  PID " << std::setw(8) << pid << L": " << count << L" entries" << std::endl;
        }
    }
    
    void PrintErrors() {
        std::wcout << L"\n=== ERRORS AND WARNINGS ===" << std::endl;
        
        int errorCount = 0;
        for (const auto& entry : entries) {
            if (entry.level == L"ERROR" || entry.level == L"CRITICAL") {
                std::wcout << L"[" << entry.timestamp << L"] [" << entry.level << L"] "
                          << L"[" << entry.component << L"] " << entry.message << std::endl;
                errorCount++;
            }
        }
        
        if (errorCount == 0) {
            std::wcout << L"No errors found!" << std::endl;
        } else {
            std::wcout << L"\nTotal errors: " << errorCount << std::endl;
        }
    }
    
    void PrintHookActivity() {
        std::wcout << L"\n=== HOOK ACTIVITY ===" << std::endl;
        
        std::map<std::wstring, int> hookCounts;
        for (const auto& entry : entries) {
            if (entry.message.find(L"Intercepted") != std::wstring::npos) {
                // Extract hook type from message
                if (entry.message.find(L"WinHttpSendRequest") != std::wstring::npos) {
                    hookCounts[L"WinHttpSendRequest"]++;
                } else if (entry.message.find(L"WinHttpReadData") != std::wstring::npos) {
                    hookCounts[L"WinHttpReadData"]++;
                } else if (entry.message.find(L"SSL_write") != std::wstring::npos) {
                    hookCounts[L"SSL_write"]++;
                } else if (entry.message.find(L"SSL_read") != std::wstring::npos) {
                    hookCounts[L"SSL_read"]++;
                } else if (entry.message.find(L"WebSocket") != std::wstring::npos) {
                    hookCounts[L"WebSocket"]++;
                }
            }
        }
        
        if (hookCounts.empty()) {
            std::wcout << L"No hook activity detected" << std::endl;
        } else {
            for (const auto& [hook, count] : hookCounts) {
                std::wcout << L"  " << std::setw(20) << hook << L": " << count << L" calls" << std::endl;
            }
        }
    }
    
    void FindRecentLogs() {
        std::wcout << L"\n=== SEARCHING FOR RECENT LOG FILES ===" << std::endl;
        
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        std::filesystem::path tempDir(tempPath);
        std::vector<std::filesystem::path> logFiles;
        
        try {
            for (const auto& entry : std::filesystem::directory_iterator(tempDir)) {
                if (entry.is_regular_file()) {
                    std::wstring filename = entry.path().filename().wstring();
                    if (filename.find(L"ai_hook_") == 0 && filename.find(L".log") != std::wstring::npos) {
                        logFiles.push_back(entry.path());
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error scanning temp directory: " << e.what() << std::endl;
        }
        
        if (logFiles.empty()) {
            std::wcout << L"No AI hook log files found in temp directory" << std::endl;
        } else {
            std::wcout << L"Found " << logFiles.size() << L" log file(s):" << std::endl;
            
            // Sort by modification time
            std::sort(logFiles.begin(), logFiles.end(), 
                [](const auto& a, const auto& b) {
                    return std::filesystem::last_write_time(a) > std::filesystem::last_write_time(b);
                });
            
            for (const auto& logPath : logFiles) {
                auto ftime = std::filesystem::last_write_time(logPath);
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now()
                );
                auto cftime = std::chrono::system_clock::to_time_t(sctp);
                
                std::wcout << L"  " << logPath.filename().wstring() 
                          << L" (Modified: " << std::put_time(std::localtime(&cftime), L"%Y-%m-%d %H:%M:%S")
                          << L", Size: " << std::filesystem::file_size(logPath) << L" bytes)" << std::endl;
            }
        }
    }
};

int wmain(int argc, wchar_t* argv[]) {
    std::wcout << L"AI Traffic Interceptor - Log Analyzer v1.0" << std::endl;
    std::wcout << L"===========================================" << std::endl;
    
    LogAnalyzer analyzer;
    
    if (argc < 2) {
        // No file specified, search for recent logs
        analyzer.FindRecentLogs();
        std::wcout << L"\nUsage: " << argv[0] << L" <logfile.log>" << std::endl;
        std::wcout << L"       " << argv[0] << L" --find-logs" << std::endl;
        return 1;
    }
    
    if (std::wstring(argv[1]) == L"--find-logs") {
        analyzer.FindRecentLogs();
        return 0;
    }
    
    // Analyze the specified log file
    std::wstring logFile = argv[1];
    analyzer.LoadLogFile(logFile);
    
    analyzer.PrintSummary();
    analyzer.PrintErrors();
    analyzer.PrintHookActivity();
    
    return 0;
} 