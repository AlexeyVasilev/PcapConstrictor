cmake_minimum_required(VERSION 3.20)

project(
    PcapConstrictor
    VERSION 0.1.0
    DESCRIPTION "CLI packet capture reducer"
    LANGUAGES CXX
)

add_executable(
    pcap-constrictor
    src/main.cpp
    src/checksum/Checksum.cpp
    src/cli/Options.cpp
    src/config/Config.cpp
    src/decode/PacketDecode.cpp
    src/pcap/ClassicPcapReader.cpp
    src/pcap/ClassicPcapWriter.cpp
    src/quic/QuicConstrictor.cpp
    src/stats/Stats.cpp
    src/tls/TlsConstrictor.cpp
)

target_compile_features(pcap-constrictor PRIVATE cxx_std_20)
set_target_properties(
    pcap-constrictor
    PROPERTIES
        CXX_EXTENSIONS OFF
)

target_include_directories(
    pcap-constrictor
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(MSVC)
    target_compile_options(pcap-constrictor PRIVATE /W4 /permissive-)
else()
    target_compile_options(pcap-constrictor PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(CTest)

if(BUILD_TESTING)
    file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" PCAP_CONSTRICTOR_SOURCE_DIR_FOR_DEFINE)
    file(TO_CMAKE_PATH "${CMAKE_CURRENT_BINARY_DIR}" PCAP_CONSTRICTOR_BINARY_DIR_FOR_DEFINE)

    add_executable(
        pcap-constrictor-tests
        tests/TestMain.cpp
        tests/TestHelpers.cpp
        tests/ConfigParsingTests.cpp
        tests/TlsFixtureTest.cpp
        tests/QuicFixtureTest.cpp
        src/config/Config.cpp
        src/decode/PacketDecode.cpp
        src/pcap/ClassicPcapReader.cpp
    )

    target_compile_features(pcap-constrictor-tests PRIVATE cxx_std_20)
    set_target_properties(
        pcap-constrictor-tests
        PROPERTIES
            CXX_EXTENSIONS OFF
    )

    target_include_directories(
        pcap-constrictor-tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    target_compile_definitions(
        pcap-constrictor-tests
        PRIVATE
            PCAP_CONSTRICTOR_SOURCE_DIR="${PCAP_CONSTRICTOR_SOURCE_DIR_FOR_DEFINE}"
            PCAP_CONSTRICTOR_BINARY_DIR="${PCAP_CONSTRICTOR_BINARY_DIR_FOR_DEFINE}"
            PCAP_CONSTRICTOR_EXE_PATH="$<TARGET_FILE:pcap-constrictor>"
    )
    add_dependencies(pcap-constrictor-tests pcap-constrictor)

    if(MSVC)
        target_compile_options(pcap-constrictor-tests PRIVATE /W4 /permissive-)
    else()
        target_compile_options(pcap-constrictor-tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME pcap_constrictor_tests
        COMMAND
            pcap-constrictor-tests
    )
endif()
