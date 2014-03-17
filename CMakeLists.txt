cmake_minimum_required(VERSION 2.8)
project(RLSAN)

set(SANITIZER_COMMON_SOURCES
    sanitizer_common/sanitizer_mac.cc
    sanitizer_common/sanitizer_common.cc
    sanitizer_common/sanitizer_deadlock_detector2.cc
    sanitizer_common/sanitizer_printf.cc
    sanitizer_common/sanitizer_procmaps_linux.cc
    sanitizer_common/sanitizer_allocator.cc
    sanitizer_common/sanitizer_libignore.cc
    sanitizer_common/sanitizer_stoptheworld_linux_libcdep.cc
    sanitizer_common/sanitizer_symbolizer_posix_libcdep.cc
    sanitizer_common/sanitizer_deadlock_detector1.cc
    sanitizer_common/sanitizer_libc.cc
    sanitizer_common/sanitizer_thread_registry.cc
    sanitizer_common/sanitizer_common_libcdep.cc
    sanitizer_common/sanitizer_win.cc
    sanitizer_common/sanitizer_procmaps_mac.cc
    sanitizer_common/sanitizer_suppressions.cc
    sanitizer_common/sanitizer_coverage.cc
    sanitizer_common/sanitizer_tls_get_addr.cc
    sanitizer_common/sanitizer_platform_limits_linux.cc
    sanitizer_common/sanitizer_symbolizer_libbacktrace.cc
    sanitizer_common/sanitizer_flags.cc
    sanitizer_common/sanitizer_symbolizer_win.cc
    sanitizer_common/sanitizer_linux.cc
    sanitizer_common/sanitizer_stacktrace.cc
    sanitizer_common/sanitizer_symbolizer_libcdep.cc
    sanitizer_common/sanitizer_posix.cc
    sanitizer_common/sanitizer_platform_limits_posix.cc
    sanitizer_common/sanitizer_symbolizer.cc
    sanitizer_common/sanitizer_linux_libcdep.cc
    sanitizer_common/sanitizer_stackdepot.cc
    sanitizer_common/sanitizer_posix_libcdep.cc
    sanitizer_common/sanitizer_stacktrace_libcdep.cc)

set(INTERCEPTION_SOURCES
    interception/interception_linux.cc)

set(RLSAN_SOURCES
    lsan/lsan.cc
    lsan/lsan_allocator.cc
    lsan/lsan_common.cc
    lsan/lsan_common_linux.cc
    lsan/lsan_interceptors.cc
    lsan/lsan_preinit.cc
    lsan/lsan_thread.cc)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_library(lsan SHARED ${SANITIZER_COMMON_SOURCES} ${INTERCEPTION_SOURCES} ${RLSAN_SOURCES})
add_definitions(-DPIC -DNDEBUG -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -fPIC -fvisibility-inlines-hidden -Wall -W -Wno-unused-parameter -Wwrite-strings -Wno-missing-field-initializers -Wno-long-long -Wnon-virtual-dtor -ffunction-sections -fdata-sections -Wall -fPIC -fno-builtin -fno-exceptions -fomit-frame-pointer -funwind-tables -fno-stack-protector -fvisibility=hidden -fno-function-sections -O3 -g -Wno-variadic-macros -Wno-non-virtual-dtor -fno-rtti -DSANITIZER_LIBBACKTRACE -fpermissive)

target_link_libraries(lsan dl pthread backtrace)

install(TARGETS lsan DESTINATION lib)
