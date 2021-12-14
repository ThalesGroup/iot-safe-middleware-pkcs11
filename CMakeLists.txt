# Minimum version of CMake 3.14.5
cmake_minimum_required (VERSION 3.14.5)
project(iot-safe-middleware-pkcs11 VERSION 0.1.0 DESCRIPTION "PKCS#11 Library for IoT SAFE")

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
enable_testing()
 
include(GNUInstallDirs)
add_subdirectory (se-access-lib)
add_subdirectory (se-pkcs11-lib)
add_subdirectory (test)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
