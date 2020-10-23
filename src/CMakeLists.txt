cmake_minimum_required(VERSION 3.10)

add_library(asio INTERFACE)
target_include_directories(asio SYSTEM INTERFACE "../asio-1.16.1/include")

aux_source_directory(. DIR_SRCS)

add_executable(securecli ${DIR_SRCS})

if(UNIX)
set(LIB_NEED 
	PkgConfig::GLOG_STATIC
 	PkgConfig::OPENSSL_STATIC
	pthread)
elseif(MSVC)
set(LIB_NEED glog openssl)
endif(UNIX)

target_link_libraries(securecli 
	asio
	${LIB_NEED}
)
