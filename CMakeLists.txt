cmake_minimum_required(VERSION 4.3)
project(Encrypted_Chat)
add_compile_options(/utf-8)

set(CMAKE_CXX_STANDARD 23)

add_executable(Encrypted_Chat_Server Server.cpp
        Include/Log.cpp Include/NetIO.cpp
        Include/ClientIO.cpp
)
add_executable(Encrypted_Chat_Client Client.cpp
        Include/Log.cpp Include/NetIO.cpp
        Include/ClientIO.cpp
)

if(WIN32)
    target_link_libraries(Encrypted_Chat_Server PRIVATE ws2_32)
    target_link_libraries(Encrypted_Chat_Client PRIVATE ws2_32)
    target_include_directories(Encrypted_Chat_Client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Include)
    target_include_directories(Encrypted_Chat_Server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Include)
endif ()
