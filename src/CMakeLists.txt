# 库的生成名字
set(OUT_NAME "pe_lib")

# src中的目录
set(SRC_DIRS
    "pe"
    "utils"
    # 后续添加更多目录
)

# pe_lib是obj库
set(all_sources "")
foreach(dir IN LISTS SRC_DIRS)
    file(GLOB_RECURSE dir_sources CONFIGURE_DEPENDS "${PROJECT_SRC_DIR}/${dir}/*.cpp")
    list(APPEND all_sources ${dir_sources})
endforeach()

# 输出所有编译的源文件
foreach(src_file ${all_sources})
    message("   + Source path:  ${src_file}")
endforeach()
# 输出所有编译的头文件
message("   + Include path: ${PROJECT_INCLUDE_DIR}")

add_library("${OUT_NAME}" OBJECT "${all_sources}")
target_include_directories("${OUT_NAME}" PUBLIC "${PROJECT_INCLUDE_DIR}")

# 临时方便调试
add_executable("main" main.cpp)
target_link_libraries("main" PRIVATE pe_lib)
target_include_directories("main" PUBLIC "${PROJECT_INCLUDE_DIR}")
