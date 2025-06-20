add_library(ai_hook SHARED
    hooks.cpp
    pipe_client.cpp
    json.cpp
    pattern_scan.cpp
)

target_include_directories(ai_hook PRIVATE ${CMAKE_SOURCE_DIR}/external/detours/src)

target_link_libraries(ai_hook PRIVATE detours ws2_32 winhttp)

if(MSVC)
    target_compile_options(ai_hook PRIVATE /MT)
endif()

set_target_properties(ai_hook PROPERTIES
    OUTPUT_NAME "ai_hook"
    PREFIX ""
    FOLDER "dll")
