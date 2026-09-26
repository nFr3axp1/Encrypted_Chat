#pragma once
#include <WinSock2.h>
#include <ws2def.h>
#include <atomic>
#include<mutex>

class WSAGuard {
public:
    WSAGuard():CreatedMessage(WSAStartup(MAKEWORD(2, 2), &MyWsaData)){};
    ~WSAGuard() {
        if (CreatedMessage == 0) {
            WSACleanup();
        }
    };
    WSAGuard(const WSAGuard&)=delete;
    WSAGuard& operator=(const WSAGuard&)=delete;
public:
    WSAData MyWsaData{};
    long long CreatedMessage=-1;
};

class SocketGuard {
public:
    sockaddr_in SocketHandleAddr{};
    SocketGuard()=default;
    ~SocketGuard(){
        CloseSocketHandle();
    }
    SocketGuard(const SocketGuard&)=delete;
    SocketGuard& operator=(const SocketGuard&)=delete;
public:
    void CloseSocketHandle() {
        const SOCKET Old=SocketHandle.exchange(INVALID_SOCKET);
        if (Old!=INVALID_SOCKET) {
            closesocket(Old);
        }
    }
    std::atomic<SOCKET> SocketHandle{INVALID_SOCKET};
    std::mutex SendMutex;
};