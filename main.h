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
#pragma comment(lib, "Ws2_32.lib")
using namespace std;

inline void color(int c);                                                      // console color function
bool init_WSA();                                                               // SOCKET initialization function
void Get_IPs(vector<string> &IPs, string &Start_IP_Addr, string &End_IP_Addr); // IP collation function
void Scan_IP_Port(vector<string> &IPs, ofstream &out_IP, const size_t &size);  // IP scan function
