#pragma once
enum class JudgeType {
    WSAStartUp,SocketCreated,SocketConnected,SocketBind,SocketListen,SocketAccept
};
bool IsOK(const JudgeType& Type, const long long &Result);