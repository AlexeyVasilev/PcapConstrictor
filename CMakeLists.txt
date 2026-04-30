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
    src/cli/Options.cpp
    src/config/Config.cpp
    src/decode/PacketDecode.cpp
    src/pcap/ClassicPcapReader.cpp
    src/pcap/ClassicPcapWriter.cpp
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
    add_executable(
        pcap-constrictor-tests
        tests/TlsFixtureTest.cpp
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
    )

    if(MSVC)
        target_compile_options(pcap-constrictor-tests PRIVATE /W4 /permissive-)
    else()
        target_compile_options(pcap-constrictor-tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(
        NAME tls_fixture_constrict
        COMMAND
            pcap-constrictor-tests
            --exe $<TARGET_FILE:pcap-constrictor>
            --fixture ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/tls/tls_test_1.pcap
            --out ${CMAKE_CURRENT_BINARY_DIR}/test-output/tls_test_1.out.pcap
    )
endif()
