cmake_minimum_required(VERSION 3.21)

project(ai_traffic_interceptor)

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
    add_subdirectory(tests)
endif()

# Custom target to set up the Python test environment
find_package(Python3 COMPONENTS Interpreter REQUIRED)

if(WIN32)
    set(PIP_EXECUTABLE "${CMAKE_SOURCE_DIR}/tests/python/venv/Scripts/pip.exe")
else()
    set(PIP_EXECUTABLE "${CMAKE_SOURCE_DIR}/tests/python/venv/bin/pip")
endif()

add_custom_target(setup_python_test
    COMMAND ${Python3_EXECUTABLE} -m venv ${CMAKE_SOURCE_DIR}/tests/python/venv
    COMMAND ${PIP_EXECUTABLE} install -r ${CMAKE_SOURCE_DIR}/tests/python/requirements.txt
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests/python
    COMMENT "Setting up Python virtual environment and installing dependencies..."
)

# Collector (C#) – built via dotnet; use custom target
add_custom_target(build_collector ALL
    COMMAND dotnet build ${CMAKE_CURRENT_SOURCE_DIR}/collector/Collector.csproj -c Release
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/collector
    COMMENT "Building C# collector..."
)

find_program(WIX_EXECUTABLE wix REQUIRED)

# Add a pre-build step to ensure the necessary WiX extension is installed
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/wix_ext_util.stamp
    COMMAND ${WIX_EXECUTABLE} extension add WixToolset.Util.wixext/6.0.1
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_BINARY_DIR}/wix_ext_util.stamp
    COMMENT "Ensuring WiX Util extension is available..."
    VERBATIM
)

add_custom_target(package_msi
    COMMAND ${WIX_EXECUTABLE} build -ext Wix.Util.dll -o ${CMAKE_BINARY_DIR}/AIInterceptor.msi ${CMAKE_SOURCE_DIR}/packaging/Product.wxs
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/packaging
    COMMENT "Building MSI package with WiX Toolset"
    DEPENDS ${CMAKE_BINARY_DIR}/wix_ext_util.stamp
)

add_dependencies(package_msi ai_injector ai_hook build_collector)
