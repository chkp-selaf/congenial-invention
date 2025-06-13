add_library(ai_hook SHARED
    dllmain.cpp
    hooks.cpp
    pipe_client.cpp
    json.cpp
    pattern_scan.cpp
)

target_include_directories(ai_hook PRIVATE ${CMAKE_SOURCE_DIR}/external/detours/include)

target_link_libraries(ai_hook PRIVATE detours ws2_32 winhttp)

set_target_properties(ai_hook PROPERTIES
    OUTPUT_NAME "ai_hook"
    PREFIX ""
    FOLDER "dll")
