add_executable(ai_injector
    injector.cpp
)

target_include_directories(ai_injector PRIVATE
    ${CMAKE_SOURCE_DIR}/external
    ${CMAKE_SOURCE_DIR}/external/detours/include
    ${CMAKE_SOURCE_DIR}/external/detours/src
)

target_link_libraries(ai_injector PRIVATE detours)

if(MSVC)
    target_compile_options(ai_injector PRIVATE /MT)
endif()

set_target_properties(ai_injector PROPERTIES FOLDER "injector")
