cmake_minimum_required(VERSION 3.10)

project(securesockscli VERSION 0.1.0 DESCRIPTION "socks5tls")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Debug)
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(UNIX)
	find_package(PkgConfig REQUIRED)
	PKG_CHECK_MODULES(GLOG_STATIC REQUIRED IMPORTED_TARGET libglog)
	PKG_CHECK_MODULES(OPENSSL_STATIC REQUIRED IMPORTED_TARGET openssl)
elseif(MSVC)
	find_package(glog REQUIRED)
	find_package(OpenSSL REQUIRED)
endif(UNIX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(USE_STANDALONE_ASIO 1)

set(SPATH "src")

configure_file(
	"${PROJECT_SOURCE_DIR}/Configure.h.in"
	"${PROJECT_SOURCE_DIR}/${SPATH}/Configure.h"
	@ONLY
)

add_subdirectory(${SPATH})

