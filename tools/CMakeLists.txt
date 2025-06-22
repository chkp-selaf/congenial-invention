add_executable(dll_diag dll_diag.cpp)
if(MSVC)
    target_compile_options(dll_diag PRIVATE /MT)
endif()
set_target_properties(dll_diag PROPERTIES FOLDER "tools")

# Log analyzer tool
add_executable(log_analyzer log_analyzer.cpp)
if(MSVC)
    target_compile_options(log_analyzer PRIVATE /MT)
    target_compile_features(log_analyzer PRIVATE cxx_std_17)  # For filesystem
endif()
set_target_properties(log_analyzer PROPERTIES FOLDER "tools") 