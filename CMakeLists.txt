cmake_minimum_required(VERSION 3.21)
project(mkpivm LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING "" FORCE)

if (MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc /MP /Ot /O2 /GL)
    add_link_options(/LTCG /OPT:REF /OPT:ICF)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -O2 -Wno-missing-field-initializers)
endif()

find_package(Zydis CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)

set(MKPIVM_HEADERS
    include/mkpivm/util.h
    include/mkpivm/arch.h
    include/mkpivm/seed.h
    include/mkpivm/ir.h
    include/mkpivm/cfg.h
    include/mkpivm/lifter.h
    include/mkpivm/vm_isa.h
    include/mkpivm/codec.h
    include/mkpivm/bytecode.h
    include/mkpivm/crypto.h
    include/mkpivm/x64_emit.h
    include/mkpivm/x86_emit.h
    include/mkpivm/vm_codegen.h
    include/mkpivm/packager.h
    include/mkpivm/pe_embed.h
)

set(MKPIVM_SOURCES
    src/seed.cpp
    src/lifter.cpp
    src/cfg.cpp
    src/vm_isa.cpp
    src/codec.cpp
    src/codec_x86.cpp
    src/crypto.cpp
    src/x64_emit.cpp
    src/x86_emit.cpp
    src/vm_codegen.cpp
    src/vm_codegen_x86.cpp
    src/packager.cpp
    src/pe_embed.cpp
)

add_executable(mkpivm src/main.cpp ${MKPIVM_SOURCES} ${MKPIVM_HEADERS})
target_include_directories(mkpivm PRIVATE include)
target_link_libraries(mkpivm PRIVATE Zydis::Zydis fmt::fmt)
