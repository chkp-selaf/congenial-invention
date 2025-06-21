add_library(ai_hook SHARED
    hooks.cpp
    pipe_client.cpp
    json.cpp
    pattern_scan.cpp
)

target_include_directories(ai_hook PRIVATE ${CMAKE_SOURCE_DIR}/external/detours/src)

target_link_libraries(ai_hook PRIVATE detours winhttp)
target_compile_features(ai_hook PRIVATE cxx_std_17)

if(MSVC)
    target_compile_options(ai_hook PRIVATE /MT)
    target_link_libraries(ai_hook PRIVATE winhttp)
endif()

set_target_properties(ai_hook PROPERTIES
    OUTPUT_NAME "ai_hook"
    PREFIX ""
    FOLDER "dll")

add_dependencies(ai_hook dll_diag)
add_custom_command(TARGET ai_hook POST_BUILD
    COMMAND $<TARGET_FILE:dll_diag> $<TARGET_FILE:ai_hook>
    COMMENT "Diagnosing architecture of ai_hook.dll"
    VERBATIM)

# Minimal test DLL for ARM64 testing
add_library(minimal_test SHARED minimal_test.cpp)
set_target_properties(minimal_test PROPERTIES FOLDER "dll")
