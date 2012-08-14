#####################################################################
# Copyright (c) 2010 Massachusetts Institute of Technology          #
#                                                                   #
# Permission is hereby granted, free of charge, to any person       #
# obtaining a copy of this software and associated documentation    #
# files (the "Software"), to deal in the Software without           #
# restriction, including without limitation the rights to use,      #
# copy, modify, merge, publish, distribute, sublicense, and/or sell #
# copies of the Software, and to permit persons to whom the         #
# Software is furnished to do so, subject to the following          #
# conditions:                                                       #
#                                                                   #
# The above copyright notice and this permission notice shall be    #
# included in all copies or substantial portions of the Software.   #
#                                                                   #
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,   #
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES   #
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND          #
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT       #
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,      #
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING      #
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR     #
# OTHER DEALINGS IN THE SOFTWARE.                                   #
#####################################################################


cmake_minimum_required(VERSION 2.6)

project(Umbra)

set(LIBRARY_OUTPUT_PATH "${PROJECT_BINARY_DIR}/bin")

option(BUILD_TEST "build test" OFF)
if (BUILD_TEST)
   enable_testing()
   add_subdirectory(test)
endif (BUILD_TEST)

option(DOUBLE_SHADOW
        "Two shadow translation"
        OFF)
if (DOUBLE_SHADOW)
  add_definitions(-DDOUBLE_SHADOW)
endif (DOUBLE_SHADOW)

option(UMBRA_CLIENT_PDG_SIMPLE
        "UMBRA Program Dependency Graph Simple"
        OFF)
if (UMBRA_CLIENT_PDG_SIMPLE)
  add_definitions(-DUMBRA_CLIENT_PDG_SIMPLE)
endif (UMBRA_CLIENT_PDG_SIMPLE)


option(UMBRA_CLIENT_NULL_1_BYTE_TO_1_BYTE
        "UMBRA NULL CLIENT for 1-byte to 1-byte mapping"
        OFF)
if (UMBRA_CLIENT_NULL_1_BYTE_TO_1_BYTE)
  add_definitions(-DUMBRA_CLIENT_NULL_1_BYTE_TO_1_BYTE)
endif (UMBRA_CLIENT_NULL_1_BYTE_TO_1_BYTE)

option(UMBRA_CLIENT_NULL_1_BYTE_TO_4_BYTE
        "UMBRA NULL CLIENT for 1-byte to 4-byte mapping"
        OFF)
if (UMBRA_CLIENT_NULL_1_BYTE_TO_4_BYTE)
  add_definitions(-DUMBRA_CLIENT_NULL_1_BYTE_TO_4_BYTE)
endif (UMBRA_CLIENT_NULL_1_BYTE_TO_4_BYTE)

option(UMBRA_CLIENT_NULL_4_BYTE_TO_1_BYTE
        "UMBRA NULL CLIENT for 4-byte to 1-byte mapping"
        OFF)
if (UMBRA_CLIENT_NULL_4_BYTE_TO_1_BYTE)
  add_definitions(-DUMBRA_CLIENT_NULL_4_BYTE_TO_1_BYTE)
endif (UMBRA_CLIENT_NULL_4_BYTE_TO_1_BYTE)

option(UMBRA_CLIENT_NULL_1_BYTE_TO_2_BIT
        "UMBRA NULL CLIENT for 1-byte to 2-bit mapping"
        OFF)
if (UMBRA_CLIENT_NULL_1_BYTE_TO_2_BIT)
  add_definitions(-DUMBRA_CLIENT_NULL_1_BYTE_TO_2_BIT)
endif (UMBRA_CLIENT_NULL_1_BYTE_TO_2_BIT)

option(UMBRA_CLIENT_COUNT
        "UMBRA COUNT CLIENT for number of reference"
        OFF)
if (UMBRA_CLIENT_COUNT)
  add_definitions(-DUMBRA_CLIENT_COUNT)
endif (UMBRA_CLIENT_COUNT)

option(UMBRA_CLIENT_CACHE_CONTENTION_DETECTION
        "UMBRA client detects cache contention"
        ON)
if (UMBRA_CLIENT_CACHE_CONTENTION_DETECTION)
  add_definitions(-DUMBRA_CLIENT_CACHE_CONTENTION_DETECTION)
endif (UMBRA_CLIENT_CACHE_CONTENTION_DETECTION)

option(UMBRA_CLIENT_THREAD_CORRELATION_DETECTION
        "UMBRA client detects thread correlation"
        ON)
if (UMBRA_CLIENT_THREAD_CORRELATION_DETECTION)
  add_definitions(-DUMBRA_CLIENT_THREAD_CORRELATION_DETECTION)
endif (UMBRA_CLIENT_THREAD_CORRELATION_DETECTION)

option(UMBRA_CLIENT_SHARE_DETECT
        "UMBRA SHARE COUNT CLIENT for detecting shared memory access"
        OFF)
if (UMBRA_CLIENT_SHARE_DETECT)
  add_definitions(-DUMBRA_CLIENT_SHARE_DETECT)
endif (UMBRA_CLIENT_SHARE_DETECT)

option(UMBRA_CLIENT_FALSE_SHARING_DETECTION
        "UMBRA FALSE SHARING DETECTION CLIENT for false sharing detection"
        ON)
if (UMBRA_CLIENT_FALSE_SHARING_DETECTION)
  add_definitions(-DUMBRA_CLIENT_FALSE_SHARING_DETECTION)
endif (UMBRA_CLIENT_FALSE_SHARING_DETECTION)

option(UMBRA_CLIENT_DEP_DETECT
        "UMBRA CLIENT for depedence graph construction"
        OFF)
if (UMBRA_CLIENT_DEP_DETECT)
  add_definitions(-DUMBRA_CLIENT_DEP_DETECT)
endif (UMBRA_CLIENT_DEP_DETECT)

option(VERBOSE_INSTRUMENTATION
        "Display the instrumentation code"
        OFF)
if (VERBOSE_INSTRUMENTATION)
  add_definitions(-DVERBOSE_INSTRUMENTATION)
endif (VERBOSE_INSTRUMENTATION)

if (NOT DEFINED DynamoRIO_DIR)
  set(DynamoRIO_DIR "${PROJECT_SOURCE_DIR}/../cmake" CACHE PATH
    "DynamoRIO installation's cmake directory")
endif (NOT DEFINED DynamoRIO_DIR)

find_package(DynamoRIO 3.0)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

if (WIN32)
  # disable stack protection: "unresolved external symbol ___security_cookie"
  # disable the warning "unreferenced formal parameter" #4100
  # disable the warning "conditional expression is constant" #4127
  # disable the warning "cast from function pointer to data pointer" #4054
  set(CL_CFLAGS "/GS- /wd4100 /wd4127 /wd4054")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CL_CFLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CL_CFLAGS}")
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif (WIN32)

if (UNIX)
  set(WARN "-Wall") # -Werror")
  set(DBG "-g3")
  set(OPT "-O3 ${DBG}")
else (UNIX)
  set(WARN "/W4 /WX")
  set(DBG "/Zi")
  set(OPT "/O2 ${DBG}")
endif (UNIX)

if (DEBUG)
  set(BASE_C_FLAGS "${WARN} ${OPT}")
else (DEBUG)
  set(BASE_C_FLAGS "${WARN} ${DBG}")
endif (DEBUG)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${BASE_C_FLAGS}")

#file(GLOB srcs core/*.c core/*.cpp clients/*.c client/*.cpp clients/hashtable/*.c)
file(GLOB base_srcs core/*.c core/*.cpp)

if (UMBRA_CLIENT_PDG_SIMPLE)
  add_library(pdg1 SHARED ${base_srcs} clients/client-pdg-simple.c)
  configure_DynamoRIO_client(pdg1)
endif (UMBRA_CLIENT_PDG_SIMPLE)



if (UMBRA_CLIENT_FALSE_SHARING_DETECTION)
  add_library(fsd SHARED ${base_srcs} clients/client-fsd.c)
  configure_DynamoRIO_client(fsd)
endif (UMBRA_CLIENT_FALSE_SHARING_DETECTION)

if (UMBRA_CLIENT_DEP_DETECT)
  add_library(depdetect SHARED ${base_srcs} clients/client-dep-detect.c)
  configure_DynamoRIO_client(depdetect)
endif (UMBRA_CLIENT_DEP_DETECT)

if (UMBRA_CLIENT_SHARE_DETECT)
  add_library(sharedetect SHARED ${base_srcs} clients/client-share-detect.c)
  configure_DynamoRIO_client(sharedetect)
endif (UMBRA_CLIENT_SHARE_DETECT)

if (UMBRA_CLIENT_CACHE_CONTENTION_DETECTION)
  add_library(ccd SHARED ${base_srcs} clients/client-ccd.c)
  configure_DynamoRIO_client(ccd)
endif (UMBRA_CLIENT_CACHE_CONTENTION_DETECTION)

if (UMBRA_CLIENT_THREAD_CORRELATION_DETECTION)
  add_library(tcd SHARED ${base_srcs} clients/client-tcd.c)
  configure_DynamoRIO_client(tcd)
endif (UMBRA_CLIENT_THREAD_CORRELATION_DETECTION)

if (UMBRA_CLIENT_COUNT)
  add_library(count SHARED ${base_srcs} clients/client-count.c)
  configure_DynamoRIO_client(count)
endif (UMBRA_CLIENT_COUNT)

if (UMBRA_CLIENT_NULL_1_BYTE_TO_1_BYTE)
  add_library(null1to1 SHARED ${base_srcs} clients/client-null-1-to-1.c)
  configure_DynamoRIO_client(null1to1)
endif (UMBRA_CLIENT_NULL_1_BYTE_TO_1_BYTE)

if (UMBRA_CLIENT_NULL_1_BYTE_TO_4_BYTE)
  add_library(null1to4 SHARED ${base_srcs} clients/client-null-1-to-4.c)
  configure_DynamoRIO_client(null1to4)
endif (UMBRA_CLIENT_NULL_1_BYTE_TO_4_BYTE)

if (UMBRA_CLIENT_NULL_4_BYTE_TO_1_BYTE)
  add_library(null4to1 SHARED ${base_srcs} clients/client-null-4-to-1.c)
  configure_DynamoRIO_client(null4to1)
endif (UMBRA_CLIENT_NULL_4_BYTE_TO_1_BYTE)

if (UMBRA_CLIENT_NULL_1_BYTE_TO_2_BIT)
  add_library(null1Bto2b SHARED ${base_srcs} clients/client-null-1B-to-2b.c)
  configure_DynamoRIO_client(null1Bto2b)
endif (UMBRA_CLIENT_NULL_1_BYTE_TO_2_BIT)





