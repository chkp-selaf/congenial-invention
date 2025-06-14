add_executable(ai_injector
    injector.cpp
)

target_include_directories(ai_injector PRIVATE ${CMAKE_SOURCE_DIR}/external/detours/include)
target_include_directories(ai_injector PRIVATE ${CMAKE_SOURCE_DIR}/external/detours/src)

target_link_libraries(ai_injector PRIVATE detours)

set_target_properties(ai_injector PROPERTIES FOLDER "injector")
