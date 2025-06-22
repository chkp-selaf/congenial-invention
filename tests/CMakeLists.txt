# GoogleTest integration via FetchContent
include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG    v1.14.0 # Or a specific commit/tag
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(unit_tests
    main.cpp
    winhttp_hooks_test.cpp
)

# Link against gtest & gmock
target_link_libraries(unit_tests PRIVATE GTest::gtest GTest::gmock winhttp)

# Enable test discovery in CTest
include(GoogleTest)
gtest_discover_tests(unit_tests)

set_target_properties(unit_tests PROPERTIES FOLDER "tests")

# ARM64 injection test
add_executable(test_arm64_injection test_arm64_injection.cpp)
target_link_libraries(test_arm64_injection PRIVATE detours)
target_compile_features(test_arm64_injection PRIVATE cxx_std_17)
set_target_properties(test_arm64_injection PROPERTIES FOLDER "tests")

# Mini client for testing DLL injection
add_executable(mini_client mini_client.cpp)
target_link_libraries(mini_client PRIVATE winhttp)
set_target_properties(mini_client PROPERTIES FOLDER "tests")

# Simple test program
add_executable(test_simple test_simple.cpp)
set_target_properties(test_simple PROPERTIES FOLDER "tests")

# Self-injection test
add_executable(test_inject_self test_inject_self.cpp)
set_target_properties(test_inject_self PROPERTIES FOLDER "tests")
