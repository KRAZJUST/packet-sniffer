cmake_minimum_required(VERSION 3.27)
project(IPK_2)

set(CMAKE_CXX_STANDARD 14)

include_directories(src)

add_executable(IPK_2
        src/arguments.cpp
        src/arguments.h
        src/packet_parser.cpp
        src/packet_parser.h
        src/packet_sniffer.cpp
        src/packet_sniffer.h
        src/sniffer.cpp
        src/sniffer.h)
