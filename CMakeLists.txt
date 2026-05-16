cmake_minimum_required(VERSION 3.20)

project(
    PcapConstrictor
    VERSION 0.1.0
    DESCRIPTION "CLI packet capture reducer"
    LANGUAGES CXX
)

include(GNUInstallDirs)

function(pcap_constrictor_apply_common_settings target_name)
    target_compile_features(${target_name} PUBLIC cxx_std_20)
    set_target_properties(
        ${target_name}
        PROPERTIES
            CXX_EXTENSIONS OFF
    )

    if(MSVC)
        target_compile_options(${target_name} PRIVATE /W4 /permissive-)
    else()
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

add_library(
    pcap-constrictor-core
    STATIC
    src/checksum/Checksum.cpp
    src/cli/Options.cpp
    src/config/Config.cpp
    src/constrict/DecisionLog.cpp
    src/decode/PacketDecode.cpp
    src/pcap/CaptureFormat.cpp
    src/pcap/ClassicPcapReader.cpp
    src/pcap/ClassicPcapWriter.cpp
    src/pcap/PcapNgReader.cpp
    src/pcap/PcapNgWriter.cpp
    src/quic/QuicConstrictor.cpp
    src/stats/Stats.cpp
    src/tls/TlsConstrictor.cpp
)

target_include_directories(
    pcap-constrictor-core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(
    pcap-constrictor-core
    PRIVATE
        PCAP_CONSTRICTOR_VERSION="${PROJECT_VERSION}"
)

pcap_constrictor_apply_common_settings(pcap-constrictor-core)

add_executable(
    pcap-constrictor
    src/main.cpp
)

target_link_libraries(
    pcap-constrictor
    PRIVATE
        pcap-constrictor-core
)

pcap_constrictor_apply_common_settings(pcap-constrictor)

include(CTest)

install(
    TARGETS pcap-constrictor
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    FILES
        README.md
        LICENSE
        config.example.ini
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

if(BUILD_TESTING)
    file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" PCAP_CONSTRICTOR_SOURCE_DIR_FOR_DEFINE)
    file(TO_CMAKE_PATH "${CMAKE_CURRENT_BINARY_DIR}" PCAP_CONSTRICTOR_BINARY_DIR_FOR_DEFINE)

    add_executable(
        pcap-constrictor-tests
        tests/TestMain.cpp
        tests/TestHelpers.cpp
        tests/ConfigParsingTests.cpp
        tests/DecisionLogFixtureTest.cpp
        tests/GoldenWorkflowTests.cpp
        tests/PcapNgFixtureTest.cpp
        tests/ReinflateChecksumPolicyTest.cpp
        tests/TruncatedTailFixtureTest.cpp
        tests/TlsContinuationPolicyTest.cpp
        tests/TlsFixtureTest.cpp
        tests/QuicFixtureTest.cpp
    )

    target_include_directories(
        pcap-constrictor-tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )

    target_link_libraries(
        pcap-constrictor-tests
        PRIVATE
            pcap-constrictor-core
    )

    target_compile_definitions(
        pcap-constrictor-tests
        PRIVATE
            PCAP_CONSTRICTOR_SOURCE_DIR="${PCAP_CONSTRICTOR_SOURCE_DIR_FOR_DEFINE}"
            PCAP_CONSTRICTOR_BINARY_DIR="${PCAP_CONSTRICTOR_BINARY_DIR_FOR_DEFINE}"
            PCAP_CONSTRICTOR_EXE_PATH="$<TARGET_FILE:pcap-constrictor>"
    )

    pcap_constrictor_apply_common_settings(pcap-constrictor-tests)

    add_test(
        NAME pcap_constrictor_tests
        COMMAND
            pcap-constrictor-tests
    )
endif()
