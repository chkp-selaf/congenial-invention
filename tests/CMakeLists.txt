# GoogleTest integration via vcpkg
find_package(GTest REQUIRED)

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
