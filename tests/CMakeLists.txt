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
