cmake_minimum_required(VERSION 3.21)

project(detours LANGUAGES C CXX)

# Path to the actual Detours source
set(DETOURS_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../detours)

add_library(detours STATIC
    ${DETOURS_SOURCE_DIR}/src/detours.cpp
    ${DETOURS_SOURCE_DIR}/src/image.cpp
    ${DETOURS_SOURCE_DIR}/src/modules.cpp
    ${DETOURS_SOURCE_DIR}/src/disasm.cpp
    ${DETOURS_SOURCE_DIR}/src/creatwth.cpp
)

# Add architecture-specific files
if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64" OR CMAKE_GENERATOR_PLATFORM MATCHES "ARM64")
    target_sources(detours PRIVATE ${DETOURS_SOURCE_DIR}/src/disolarm64.cpp)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_GENERATOR_PLATFORM MATCHES "x64")
    target_sources(detours PRIVATE ${DETOURS_SOURCE_DIR}/src/disolx64.cpp)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "X86" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i686" OR CMAKE_GENERATOR_PLATFORM MATCHES "Win32")
    target_sources(detours PRIVATE ${DETOURS_SOURCE_DIR}/src/disolx86.cpp)
endif()

# Include directory for consumers
target_include_directories(detours PUBLIC ${DETOURS_SOURCE_DIR}/src)

# Define architecture macros
if(CMAKE_GENERATOR_PLATFORM MATCHES "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
    target_compile_definitions(detours PRIVATE DETOURS_ARM64 DETOURS_64BIT _ARM64_)
elseif(CMAKE_GENERATOR_PLATFORM MATCHES "x64" OR CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(detours PRIVATE DETOURS_X64 DETOURS_64BIT _AMD64_)
elseif(CMAKE_GENERATOR_PLATFORM MATCHES "Win32" OR CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_compile_definitions(detours PRIVATE DETOURS_X86 DETOURS_32BIT _X86_)
endif()

# Disable warnings from detours (optional)
if(MSVC)
    target_compile_definitions(detours PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(detours PRIVATE /wd4201 /wd4819)
endif() 