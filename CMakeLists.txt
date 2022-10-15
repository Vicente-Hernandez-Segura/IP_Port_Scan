cmake_minimum_required(VERSION 3.1)

project(IP_Port_Scan)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra -static -static-libgcc -static-libstdc++ -Wl,-Bstatic -lstdc++ -lpthread")

add_executable(IP_Port_Scan main.cpp)

target_link_libraries(IP_Port_Scan winmm.lib sapi wsock32 ws2_32 crypt32 ws2_32 gdiplus Ws2_32.lib)
