cmake_minimum_required (VERSION 3.0)
project (Debugger)

add_compile_options(-std=c++14)

include_directories(ext/libelfin ext/linenoise include)
add_executable(dbg src/main.cpp ext/linenoise/linenoise.c)

add_custom_target(
   libelfin
   COMMAND make
   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/ext/libelfin
)
target_link_libraries(dbg
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/dwarf/libdwarf++.so
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/elf/libelf++.so)
add_dependencies(dbg libelfin)