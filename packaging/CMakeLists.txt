# packaging/CMakeLists.txt

find_program(WIX_EXECUTABLE wix REQUIRED)

add_custom_target(package_msi
    COMMAND ${WIX_EXECUTABLE} build -o ${CMAKE_BINARY_DIR}/AIInterceptor.msi Product.wxs
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/packaging
    COMMENT "Building MSI package with WiX Toolset"
)

# --- Define full dependency chain for packaging ---
add_dependencies(package_msi ai_injector ai_hook build_proxy copy_preload build_collector) 