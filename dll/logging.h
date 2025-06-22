#pragma once

// Prevent Windows macros from conflicting
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#ifndef _INC_WINDOWS
#endif
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif
#include <string>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <fstream>
#include <algorithm>  // For std::min

enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERR = 4,  // Renamed from ERROR to avoid Windows macro conflict
    CRITICAL = 5
};

class Logger {
private:
    static Logger* instance;
    static std::mutex mutex;
    
    LogLevel minLevel;
    bool enableConsole;
    bool enableFile;
    bool enableDebugOutput;
    bool enableETW;
    std::wofstream logFile;
    std::wstring logFilePath;
    
    Logger() : minLevel(LogLevel::DEBUG), enableConsole(false), 
               enableFile(true), enableDebugOutput(true), enableETW(true) {
        InitializeLogFile();
    }
    
    void InitializeLogFile() {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::wstringstream ss;
        ss << tempPath << L"ai_hook_" << GetCurrentProcessId() << L"_";
        ss << std::put_time(std::localtime(&time_t), L"%Y%m%d_%H%M%S");
        ss << L".log";
        
        logFilePath = ss.str();
        logFile.open(logFilePath, std::ios::app);
    }
    
    const wchar_t* LevelToString(LogLevel level) {
        switch(level) {
            case LogLevel::TRACE: return L"TRACE";
            case LogLevel::DEBUG: return L"DEBUG";
            case LogLevel::INFO: return L"INFO";
            case LogLevel::WARN: return L"WARN";
            case LogLevel::ERR: return L"ERROR";
            case LogLevel::CRITICAL: return L"CRITICAL";
            default: return L"UNKNOWN";
        }
    }
    
public:
    static Logger* GetInstance() {
        std::lock_guard<std::mutex> lock(mutex);
        if (!instance) {
            instance = new Logger();
        }
        return instance;
    }
    
    void SetMinLevel(LogLevel level) { minLevel = level; }
    void SetConsoleEnabled(bool enabled) { enableConsole = enabled; }
    void SetFileEnabled(bool enabled) { enableFile = enabled; }
    void SetDebugOutputEnabled(bool enabled) { enableDebugOutput = enabled; }
    void SetETWEnabled(bool enabled) { enableETW = enabled; }
    
    std::wstring GetLogFilePath() const { return logFilePath; }
    
    void Log(LogLevel level, const std::wstring& component, const std::wstring& message) {
        if (level < minLevel) return;
        
        std::lock_guard<std::mutex> lock(mutex);
        
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::wstringstream ss;
        ss << L"[" << std::put_time(std::localtime(&time_t), L"%Y-%m-%d %H:%M:%S");
        ss << L"." << std::setfill(L'0') << std::setw(3) << ms.count() << L"] ";
        ss << L"[" << LevelToString(level) << L"] ";
        ss << L"[PID:" << GetCurrentProcessId() << L"] ";
        ss << L"[TID:" << GetCurrentThreadId() << L"] ";
        ss << L"[" << component << L"] ";
        ss << message;
        
        std::wstring logLine = ss.str();
        
        if (enableDebugOutput) {
            OutputDebugStringW((logLine + L"\n").c_str());
        }
        
        if (enableFile && logFile.is_open()) {
            logFile << logLine << std::endl;
            logFile.flush();
        }
        
        if (enableConsole) {
            if (level >= LogLevel::ERR) {
                fwprintf(stderr, L"%s\n", logLine.c_str());
            } else {
                wprintf(L"%s\n", logLine.c_str());
            }
        }
        
        if (enableETW) {
            // ETW logging is already implemented in hooks.cpp
            extern void EtwTraceMessage(PCWSTR message);
            EtwTraceMessage(logLine.c_str());
        }
    }
    
    void LogFormat(LogLevel level, const std::wstring& component, const wchar_t* format, ...) {
        wchar_t buffer[4096];
        va_list args;
        va_start(args, format);
        vswprintf_s(buffer, format, args);
        va_end(args);
        
        Log(level, component, buffer);
    }
    
    void LogData(LogLevel level, const std::wstring& component, const std::wstring& message, 
                 const void* data, size_t dataLen) {
        std::wstringstream ss;
        ss << message << L" [Data: ";
        
        if (data && dataLen > 0) {
            const unsigned char* bytes = static_cast<const unsigned char*>(data);
            ss << L"Length=" << dataLen << L", Hex=";
            for (size_t i = 0; i < std::min(dataLen, size_t(32)); ++i) {
                ss << std::hex << std::setw(2) << std::setfill(L'0') << (int)bytes[i];
            }
            if (dataLen > 32) ss << L"...";
        } else {
            ss << L"null";
        }
        ss << L"]";
        
        Log(level, component, ss.str());
    }
    
    ~Logger() {
        if (logFile.is_open()) {
            Log(LogLevel::INFO, L"Logger", L"Shutting down logger");
            logFile.close();
        }
    }
};

// Static members
inline Logger* Logger::instance = nullptr;
inline std::mutex Logger::mutex;

// Convenience macros
#define LOG_TRACE(component, message) Logger::GetInstance()->Log(LogLevel::TRACE, component, message)
#define LOG_DEBUG(component, message) Logger::GetInstance()->Log(LogLevel::DEBUG, component, message)
#define LOG_INFO(component, message) Logger::GetInstance()->Log(LogLevel::INFO, component, message)
#define LOG_WARN(component, message) Logger::GetInstance()->Log(LogLevel::WARN, component, message)
#define LOG_ERROR(component, message) Logger::GetInstance()->Log(LogLevel::ERR, component, message)
#define LOG_CRITICAL(component, message) Logger::GetInstance()->Log(LogLevel::CRITICAL, component, message)

#define LOG_TRACE_F(component, format, ...) Logger::GetInstance()->LogFormat(LogLevel::TRACE, component, format, __VA_ARGS__)
#define LOG_DEBUG_F(component, format, ...) Logger::GetInstance()->LogFormat(LogLevel::DEBUG, component, format, __VA_ARGS__)
#define LOG_INFO_F(component, format, ...) Logger::GetInstance()->LogFormat(LogLevel::INFO, component, format, __VA_ARGS__)
#define LOG_WARN_F(component, format, ...) Logger::GetInstance()->LogFormat(LogLevel::WARN, component, format, __VA_ARGS__)
#define LOG_ERROR_F(component, format, ...) Logger::GetInstance()->LogFormat(LogLevel::ERR, component, format, __VA_ARGS__)
#define LOG_CRITICAL_F(component, format, ...) Logger::GetInstance()->LogFormat(LogLevel::CRITICAL, component, format, __VA_ARGS__)

#define LOG_DATA(level, component, message, data, len) Logger::GetInstance()->LogData(level, component, message, data, len) 