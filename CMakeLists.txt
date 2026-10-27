cmake_minimum_required(VERSION 3.25)

# Load the IDA SDK bootstrap (requires the IDASDK environment variable)
include("$ENV{IDASDK}/src/cmake/idasdk_init.cmake")

project(ghidradec-idafree C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(idasdk REQUIRED)

# static CRT (/MT). Not IDA_USE_STATIC_RUNTIME: the SDK's x64_win_64_s libs
# ship no ida.lib. ida.lib is only an import library, so it works with /MT.
# Must come after find_package (which sets /MD) and before the targets.
option(GD_STATIC_CRT "Link the MSVC runtime statically (/MT)" OFF)
if(MSVC AND GD_STATIC_CRT)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Ghidra installation: its decompiler C++ sources (sleigh library) are compiled
# into the plugin, and its path is the default runtime "Ghidra folder".
if(NOT GHIDRA_DIR)
    if(DEFINED ENV{GHIDRA_DIR})
        set(GHIDRA_DIR "$ENV{GHIDRA_DIR}")
    else()
        message(FATAL_ERROR "GHIDRA_DIR is not set: point it to your Ghidra installation (e.g. C:/path/to/ghidra_12.1.4_PUBLIC).")
    endif()
endif()
file(TO_CMAKE_PATH "${GHIDRA_DIR}" GHIDRA_DIR)
set(GHIDRA_DIR "${GHIDRA_DIR}" CACHE PATH "Ghidra installation folder" FORCE)

set(GHIDRA_DECOMPILE_DIR "${GHIDRA_DIR}/Ghidra/Features/Decompiler/src/decompile")
set(GHIDRA_CPP "${GHIDRA_DECOMPILE_DIR}/cpp")
if(NOT EXISTS "${GHIDRA_CPP}/sleigh.cc")
    message(FATAL_ERROR "Ghidra decompiler sources not found in ${GHIDRA_CPP}. Set GHIDRA_DIR.")
endif()
# its version: a prebuilt plugin warns when it runs with another Ghidra
set(GHIDRA_VERSION "")
if(EXISTS "${GHIDRA_DIR}/Ghidra/application.properties")
    file(STRINGS "${GHIDRA_DIR}/Ghidra/application.properties" GHIDRA_VERSION_LINE REGEX "^application[.]version=")
    string(REGEX REPLACE "^application[.]version=" "" GHIDRA_VERSION "${GHIDRA_VERSION_LINE}")
    string(STRIP "${GHIDRA_VERSION}" GHIDRA_VERSION)
endif()
message(STATUS "Ghidra: ${GHIDRA_DIR} (version ${GHIDRA_VERSION})")

#-------------------------------------------------------------------------------
# ghidra_sleigh: Ghidra's sleigh/p-code library + the Ghidra side of the
# decompiler protocol (sleighinterface.cpp). No IDA headers in here.
#-------------------------------------------------------------------------------
set(GHIDRA_SOURCES
    # sleigh
    sleigh.cc pcodeparse.cc pcodecompile.cc sleighbase.cc slghsymbol.cc
    slghpatexpress.cc slghpattern.cc semantics.cc context.cc slaformat.cc
    compression.cc filemanage.cc
    # core
    xml.cc marshal.cc space.cc float.cc address.cc pcoderaw.cc translate.cc
    opcodes.cc globalcontext.cc crc32.cc
    # emulation
    loadimage.cc memstate.cc emulate.cc opbehavior.cc
)
list(TRANSFORM GHIDRA_SOURCES PREPEND "${GHIDRA_CPP}/")

set(GHIDRA_ZLIB_SOURCES adler32.c deflate.c inffast.c inflate.c inftrees.c trees.c zutil.c)
list(TRANSFORM GHIDRA_ZLIB_SOURCES PREPEND "${GHIDRA_DECOMPILE_DIR}/zlib/")

add_library(ghidra_sleigh STATIC
    ${GHIDRA_SOURCES}
    ${GHIDRA_ZLIB_SOURCES}
    src/sleighinterface.h
    src/sleighinterface.cpp
)
target_include_directories(ghidra_sleigh PUBLIC "${GHIDRA_CPP}" src)
target_compile_definitions(ghidra_sleigh PRIVATE
    LOCAL_ZLIB NO_GZIP _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
set_target_properties(ghidra_sleigh PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(MSVC)
    target_compile_options(ghidra_sleigh PRIVATE /EHsc /bigobj /utf-8 /w)
endif()

#-------------------------------------------------------------------------------
# The IDA plugin
#-------------------------------------------------------------------------------
# installed as ghidradec.dll, like the original plugin
ida_add_plugin(ghidradec-idafree
    OUTPUT_NAME ghidradec
    SOURCES
        src/defs.h
        src/defs.cpp
        src/ghidradec_icon.h
        src/plugin_config.h
        src/plugin_config.cpp
        src/decompiler.h
        src/decompiler.cpp
        src/code_viewer.h
        src/code_viewer.cpp
        src/idaplugin.h
        src/idaplugin.cpp
        src/json.hpp
        src/json.cpp
        src/pairdiff.h
        src/pairdiff.cpp
        src/localnames.h
        src/localnames.cpp
        src/api.h
        src/api.cpp
        src/filedec.h
        src/filedec.cpp
        src/ghidra_locate.h
        src/ghidra_locate.cpp
)

target_link_libraries(ghidradec-idafree PRIVATE ghidra_sleigh)
target_compile_definitions(ghidradec-idafree PRIVATE
    NOMINMAX WIN32_LEAN_AND_MEAN
    GHIDRADEC_DEFAULT_GHIDRA_DIR="${GHIDRA_DIR}"
    GHIDRADEC_GHIDRA_VERSION="${GHIDRA_VERSION}")
if(MSVC)
    target_compile_options(ghidradec-idafree PRIVATE /bigobj)
endif()

# Put the plugin in <project>/bin instead of %IDASDK%/src/bin/plugins
set_target_properties(ghidradec-idafree PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
