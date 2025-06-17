add_executable(ai_injector
    injector.cpp
)

target_include_directories(ai_injector PRIVATE 
    ${CMAKE_SOURCE_DIR}/external/detours/include
    ${CMAKE_SOURCE_DIR}/external/detours/src
    ${CMAKE_SOURCE_DIR}/dll # For json.h
)

# Add the json source file to the injector's sources
target_sources(ai_injector PRIVATE
    ${CMAKE_SOURCE_DIR}/dll/json.cpp
)

target_link_libraries(ai_injector PRIVATE detours)

set_target_properties(ai_injector PROPERTIES FOLDER "injector")
