#include "main.h"

unsigned Port; // scan port

std::atomic_int32_t Search_Compelet; // number of scans completed
std::atomic_int32_t Open_IP;         // Number of open ports
std::mutex mtx;                      // thread mutex

void color(int c) {
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), c);
  return;
}

void Get_IPs(std::vector<std::string> &IPs, std::string &Start_IP_Addr, std::string &End_IP_Addr) {
  color(11);
  std::cout << std::endl
       << "Sorting out IP addresses..." << std::endl;
  unsigned long Start_IP = htonl(inet_addr(Start_IP_Addr.c_str()));
  unsigned long End_IP = htonl(inet_addr(End_IP_Addr.c_str()));
  if (Start_IP > End_IP) {
    color(12);
    std::cout << "Error : Start_IP must be smaller than End_IP!";
  } else {
    in_addr addr;
    for (unsigned long Index = Start_IP; Index <= End_IP; Index++) {
      addr.S_un.S_addr = ntohl(Index);
      IPs.push_back(inet_ntoa(addr));
    }
  }
}

bool init_WSA() {
  WSADATA wsaData;
  WORD wVersionRequested = MAKEWORD(1, 1);
  if (WSAStartup(wVersionRequested, &wsaData)) {
    color(12);
    std::cout << "Winsock Initialization failed." << std::endl;
    system("pause");
    return false;
  } else
    return true;
}

void Scan_IP_Port(std::vector<std::string> &IPs, std::ofstream &out_IP, const size_t &size) {
  SOCKET mysocket = NULL;
  sockaddr_in my_addr;
  while (Search_Compelet != size) {
    std::string &IP = IPs[Search_Compelet];
    Search_Compelet++;
    size_t TimeOut = 1000; // Set timeout to 1s
    if ((mysocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET &&
        setsockopt(mysocket, SOL_SOCKET, SO_SNDTIMEO, (char *)&TimeOut, sizeof(size_t) == SOCKET_ERROR)) {
      color(12);
      std::cout << "socket is invalid." << std::endl;
    }
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(Port);
    my_addr.sin_addr.s_addr = inet_addr(IP.c_str());
    if (connect(mysocket, (sockaddr *)&my_addr, sizeof(sockaddr)) != SOCKET_ERROR) {
      Open_IP++;
      std::lock_guard<std::mutex> temp(mtx);
      color(11);
      std::cout << IP << " Port " << Port << " is open\n";
      out_IP << IP << std::endl;
    } else {
      std::lock_guard<std::mutex> temp(mtx);
      color(14);
      std::cout << IP << " connect failed!\n";
    }
  }
  closesocket(mysocket);
  return;
}

int main() {
  unsigned thread_number;
  color(14);
  std::cout << "Welcome to IP Segment Scanner (BY: Ho229)" << std::endl;
  if (init_WSA()) {
    std::ifstream in_IP("IP.txt", std::ios::in);
    if (in_IP.is_open()) {
      std::vector<std::string> IPs;
      std::ofstream out_IP("Result.txt", std::ios::trunc);
      std::string Start_IP_Addr, End_IP_Addr;
      std::cout << "Please enter the number of scan threads (WARNING):";
      std::cin >> thread_number;
      thread_number > 1400 ? thread_number = 1400 : NULL; // Set the maximum number of threads to 1400
      std::cout << "Please enter the port to scan:";
      std::cin >> Port;
      while (!in_IP.eof()) {
        in_IP >> Start_IP_Addr >> End_IP_Addr;
        Get_IPs(IPs, Start_IP_Addr, End_IP_Addr);
        color(13);
        std::cout << "Normal Seach: About To Seach " << IPs.size() << " IP Using " << thread_number << " Threads" << std::endl;
        color(11);
        Open_IP = 0;
        Search_Compelet = 0;
        std::thread *Scan_Thread = new std::thread[thread_number];

        try {
          /*Create a scan thread*/
          for (size_t i = 0; i < thread_number; i++) {
            Scan_Thread[i] = std::thread([&]() {
              Scan_IP_Port(IPs, out_IP, IPs.size());
            });
          }
          /*waiting for scan thread*/
          for (size_t i = 0; i < thread_number; i++) {
            if (Scan_Thread[i].joinable())
              Scan_Thread[i].join();
          }
        } catch (const std::exception &err) {
          color(12);
          std::cout << "System Error:" << err.what() << std::endl;
        }

        IPs.clear();
        delete[] Scan_Thread;
        color(13);
        std::cout << Start_IP_Addr << " -->> " << End_IP_Addr << " Search Complete.Found " << Open_IP << "Result." << std::endl;
      }
      in_IP.close();
      out_IP.close();
      std::cout << "==================  Scan complete! =================" << std::endl;
    } else {
      color(12);
      std::cout << "Could not open file! (IP.txt)" << std::endl;
    }
    WSACleanup();
    system("pause");
  }
  return EXIT_SUCCESS;
}
