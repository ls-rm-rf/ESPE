cmake_minimum_required(VERSION 3.10)
project(espe6 C)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2 -g")

# 查找依赖包
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

# 包含目录
include_directories(.)
include_directories(common)
include_directories(ring)

# 源文件列表
set(COMMON_SOURCES
    common/cli.c
    common/net.c
    common/field.c
    common/poly.c
    common/util.c
)

set(RING_SOURCES
    ring/lsag.c
)

# 可执行文件1: keymgr
add_executable(keymgr
    keymgr/keymgr.c
    ${COMMON_SOURCES}
    ${RING_SOURCES}
)

# 可执行文件2: abc
add_executable(abc
    abc/participant.c
    ${COMMON_SOURCES}
    ${RING_SOURCES}
)

# 测试程序
add_executable(test_basic
    test_basic.c
    ${COMMON_SOURCES}
    ${RING_SOURCES}
)

# 链接库
target_link_libraries(keymgr ${LIBSODIUM_LIBRARIES} m)
target_link_libraries(abc ${LIBSODIUM_LIBRARIES} m)
target_link_libraries(test_basic ${LIBSODIUM_LIBRARIES} m)

# 设置输出目录
set_target_properties(keymgr abc test_basic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# 创建bin目录
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
