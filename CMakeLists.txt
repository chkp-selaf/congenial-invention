cmake_minimum_required(VERSION 3.21)

project(ai_traffic_interceptor)

if(MSVC)
    # Use dynamic CRT to ensure availability of debug CRT functions like _CrtDbgReport
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL$<$<CONFIG:Debug>:Debug>")
endif()

# Enable folders in IDEs
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# vcpkg integration (honors VCPKG_ROOT if set)
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND EXISTS "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain")
endif()

# Windows-specific dependencies and projects
if(WIN32)
    message(STATUS "Windows platform detected. Including Windows-specific C/C++ targets.")
    
    set(CMAKE_C_STANDARD 17)
    set(CMAKE_C_STANDARD_REQUIRED ON)
    set(CMAKE_C_EXTENSIONS OFF)

    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)

    # Dependencies
    add_subdirectory(external/detours EXCLUDE_FROM_ALL)

    # Subdirectories
    add_subdirectory(injector)
    add_subdirectory(dll)
    add_subdirectory(renderer)
    add_subdirectory(tests)

    # Only add packaging if WiX toolset is available
    find_program(WIX_EXECUTABLE wix)
    if(WIX_EXECUTABLE)
        add_subdirectory(packaging)
    else()
        message(WARNING "WiX toolset not found; skipping packaging targets.")
    endif()
    add_subdirectory(tools)
endif()

# Copy config directory to build output
add_custom_target(copy_config ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/config
            ${CMAKE_BINARY_DIR}/config
    COMMENT "Copying config directory"
)

# Attempt to locate Python3 for test environment; proceed if found, otherwise warn and skip the test venv target.
find_package(Python3 COMPONENTS Interpreter)
# If Python is missing we will only skip the test setup, it's not required for core build.

if(WIN32)
    set(PIP_EXECUTABLE "${CMAKE_SOURCE_DIR}/tests/python/venv/Scripts/pip.exe")
else()
    set(PIP_EXECUTABLE "${CMAKE_SOURCE_DIR}/tests/python/venv/bin/pip")
endif()

if(Python3_FOUND)
    add_custom_target(setup_python_test
        COMMAND ${Python3_EXECUTABLE} -m venv ${CMAKE_SOURCE_DIR}/tests/python/venv
        COMMAND ${PIP_EXECUTABLE} install -r ${CMAKE_SOURCE_DIR}/tests/python/requirements.txt
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests/python
        COMMENT "Setting up Python virtual environment and installing dependencies..."
    )
else()
    message(WARNING "Python 3 interpreter not found; skipping Python test environment setup.")
endif()

# Collector (C#) – built via dotnet; use custom target
add_custom_target(build_collector ALL
    COMMAND dotnet publish ${CMAKE_CURRENT_SOURCE_DIR}/collector/Collector.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ${CMAKE_BINARY_DIR}/collector
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Publishing C# collector to build/collector"
)

add_custom_target(build_proxy ALL
    COMMAND dotnet publish ${CMAKE_CURRENT_SOURCE_DIR}/proxy/Proxy.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ${CMAKE_BINARY_DIR}/proxy
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Publishing OpenAI-compatible proxy"
)

add_dependencies(build_proxy build_collector)
