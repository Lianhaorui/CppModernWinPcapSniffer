cmake_minimum_required(VERSION 3.16)

project(NetworkSniffer VERSION 1.0.0 LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Copy resources next to the generated resource script so the relative
# "app.ico" reference works even when the repository path contains spaces.
configure_file(resources/app.rc "${CMAKE_CURRENT_BINARY_DIR}/app.rc" COPYONLY)
configure_file(resources/app.ico "${CMAKE_CURRENT_BINARY_DIR}/app.ico" COPYONLY)

add_executable(NetworkSniffer WIN32
    src/CppModernWinPcapSniffer.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/app.rc"
)

target_link_libraries(NetworkSniffer PRIVATE
    gdi32
    comctl32
    ws2_32
    uxtheme
)

if(MINGW)
    target_compile_options(NetworkSniffer PRIVATE -municode)
    target_link_options(NetworkSniffer PRIVATE -municode)
endif()

set_target_properties(NetworkSniffer PROPERTIES
    OUTPUT_NAME "CppModernWinPcapSniffer"
)
