#include<Log.h>
#include<winsock2.h>
#include <iostream>

bool IsOK(const JudgeType& Type, const long long &Result) {
    if(Type==JudgeType::WSAStartUp&&Result!=0) {
        std::cout<<"WSAStartup failed:"<<Result<<std::endl;
        return false;
    }
    else if (Type==JudgeType::SocketCreated&&Result==INVALID_SOCKET) {
        std::cout<<"SocketCreated failed:"<<WSAGetLastError()<<std::endl;
        return false;
    }
    else if (Type==JudgeType::SocketConnected&&Result==SOCKET_ERROR) {
        std::cout<<"SocketConnected failed:"<<WSAGetLastError()<<std::endl;
        return false;
    }
    else if (Type==JudgeType::SocketBind&&Result==SOCKET_ERROR) {
        std::cout<<"SocketBind failed:"<<WSAGetLastError()<<std::endl;
        return false;
    }
    else if (Type==JudgeType::SocketListen&&Result==SOCKET_ERROR) {
        std::cout<<"SocketListen failed:"<<WSAGetLastError()<<std::endl;
        return false;
    }
    else if (Type==JudgeType::SocketAccept&&Result==SOCKET_ERROR) {
        if (WSAGetLastError()==WSAEINTR) {
            std::cout<<"SocketAccept Quit!,ID:"<<WSAGetLastError()<<std::endl;
            return false;
        }else {
            std::cout<<"SocketAccept failed:"<<WSAGetLastError()<<std::endl;
            return false;
        }
    }
    return true;
}