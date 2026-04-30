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
    src/pcap/ClassicPcapReader.cpp
    src/pcap/ClassicPcapWriter.cpp
    src/stats/Stats.cpp
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
