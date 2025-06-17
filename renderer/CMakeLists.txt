# renderer/CMakeLists.txt
file(GLOB PRELOAD_SCRIPTS "${CMAKE_CURRENT_SOURCE_DIR}/*.js")

add_custom_target(copy_preload ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/renderer
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${PRELOAD_SCRIPTS}
            ${CMAKE_BINARY_DIR}/renderer
    COMMENT "Copying Electron preload scripts to build/renderer"
)

# Make sure this runs before any component that needs it
add_dependencies(ai_injector copy_preload) 