enable_testing()

add_executable(
    unit_tests
    pe.test.cpp
)

# 引入待测试的函数
target_include_directories(unit_tests PUBLIC "${PROJECT_INCLUDE_DIR}")
target_link_libraries(unit_tests PRIVATE pe_lib)
add_test(test_all unit_tests)

# 测试第三方库
target_include_directories(unit_tests PUBLIC "${PROJECT_3RD_DIR}/spdlog.git/include")
target_link_libraries(unit_tests PRIVATE spdlog::spdlog)

# 自定义测试命令
add_custom_target(test COMMAND "$<TARGET_FILE:unit_tests>")