#pragma once
#include <WinSock2.h>
#include <ws2def.h>

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
        if (SocketHandle!=INVALID_SOCKET) {
            closesocket(SocketHandle);
            SocketHandle=INVALID_SOCKET;
        }
    }
    SOCKET SocketHandle=INVALID_SOCKET;
};