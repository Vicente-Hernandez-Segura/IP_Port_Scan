#pragma once

#include <Windows.h>
#include <atomic>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <winsock.h>

inline void color(int c);                                                      // console color function
bool init_WSA();                                                               // SOCKET initialization function
void Get_IPs(std::vector<std::string> &IPs, std::string &Start_IP_Addr, std::string &End_IP_Addr); // IP collation function
void Scan_IP_Port(std::vector<std::string> &IPs, std::ofstream &out_IP, const size_t &size);  // IP scan function
