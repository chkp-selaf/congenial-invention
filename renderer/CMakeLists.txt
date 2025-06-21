# renderer/CMakeLists.txt
file(GLOB PRELOAD_SCRIPTS "${CMAKE_CURRENT_SOURCE_DIR}/*.js")

# The copy_preload target has been removed as it was causing CI build failures
# Preload scripts are now handled differently

# Ensure destination directory exists
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/renderer)

# Copy preload.js to the build directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/preload.js 
               ${CMAKE_BINARY_DIR}/renderer/preload.js 
               COPYONLY) 