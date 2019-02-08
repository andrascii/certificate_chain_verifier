cmake_minimum_required(VERSION 3.2)

###########################################################################
MACRO(add_msvc_precompiled_header PrecompiledHeader PrecompiledSource SourcesVar)
  IF(MSVC)
    GET_FILENAME_COMPONENT(PrecompiledBasename ${PrecompiledHeader} NAME_WE)
    SET(PrecompiledBinary "$(IntDir)/${PrecompiledBasename}.pch")
    SET(Sources ${${SourcesVar}})

    SET_SOURCE_FILES_PROPERTIES(
		${PrecompiledSource}
		PROPERTIES COMPILE_FLAGS "/Yc\"${PrecompiledHeader}\" /Fp\"${PrecompiledBinary}\""
		OBJECT_OUTPUTS "${PrecompiledBinary}"
	)
	   
    SET_SOURCE_FILES_PROPERTIES(
		${Sources}
        PROPERTIES COMPILE_FLAGS "/Yu\"${PrecompiledHeader}\" /FI\"${PrecompiledHeader}\" /Fp\"${PrecompiledBinary}\""
        OBJECT_DEPENDS "${PrecompiledBinary}"
	)  
		
    # Add precompiled header to SourcesVar
    LIST(APPEND ${SourcesVar} ${PrecompiledSource})
  ENDIF(MSVC)
ENDMACRO(add_msvc_precompiled_header)
###########################################################################

set(CMAKE_SYSTEM_VERSION 7.0 CACHE TYPE INTERNAL FORCE)

set(APPNAME certificate_chain_verifier)
project(${APPNAME})

set(SOURCES_DIR src)
set(INCLUDE_DIR include)

find_package(OpenSSL REQUIRED)

message("*********************************************************************")
message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message("OpenSSL::SSL: ${OPENSSL_SSL_LIBRARY}")
message("OpenSSL::Crypto: ${OPENSSL_CRYPTO_LIBRARY}")
message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")
message("*********************************************************************")

aux_source_directory(${SOURCES_DIR} SOURCES_LIST)
file(GLOB_RECURSE HEADERS_LIST "include/*.h")

# work with precompiled headers in MSVC
list(REMOVE_ITEM SOURCES_LIST src/stdafx.cpp)
add_msvc_precompiled_header("stdafx.h" "src/stdafx.cpp" SOURCES_LIST)

source_group("Precompiled Headers" FILES include/stdafx.h src/stdafx.cpp)

add_executable(
	${APPNAME}
	${SOURCES_LIST}
	${HEADERS_LIST}
)

if(MSVC)
	add_definitions(
		/EHsc
		/MP
		/std:c++latest
		/Zi
		/W4
		/WX
	)
	
	set_target_properties(
		${APPNAME}
		PROPERTIES COMPILE_FLAGS "/FI\"stdafx.h\""
	)
	
	set_target_properties(
		${APPNAME}
		PROPERTIES WIN32_EXECUTABLE YES
		LINK_FLAGS "/DEBUG /ENTRY:mainCRTStartup /MAP /SUBSYSTEM:CONSOLE"
	)
endif()

include_directories(
	${INCLUDE_DIR}
	${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(
	${APPNAME}
	${OPENSSL_LIBRARIES}
	OpenSSL::SSL
	OpenSSL::Crypto
)