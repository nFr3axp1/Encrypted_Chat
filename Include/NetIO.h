#pragma once
#include<cstdint>
#include<tuple>
#include<vector>
#include<string>
#include<NetGuard.h>
#include<optional>

enum class SenderTypes {
    Client,Server
};
enum class ReceiverTypes {
    Client,Server
};

enum class ClientMessageTypes {
    Login,CheckID,Normal,
    ClientSafeQuit,ClientErrorQuit,
    ReplyProbe
};

enum class ServerMessageTypes {
    //转发
    Forward,
    //登陆
    LoginSuccessfulToken,LoginFailedToken_IDis0,LoginFailedToken_UsedID,
    //ID检验
    LegalTargetID,IllegalTargetID_IDis0,IllegalTargetID_Invalid,IllegalTargetID_TargetSelf,
    //发送消息
    ForwardSuccessfully,ForwardFailed,
    //服务器退出
    ServerSafeQuit,ServerErrorQuit,
    //探测包
    Probe
};

struct Message {
    uint32_t SenderType;
    uint32_t MessageType;
    uint32_t UserIDSender=0;
    uint32_t UserIDReceiver=0;
    static constexpr int HeadNum=5;//头参数数量

    std::string TextMessage;
};


std::tuple<std::vector<char>,int> ConvertMessagesToNetStream(const Message& message);
bool SendMessages(SocketGuard& Socket,const char* MessagesNetStreamHead_ptr,const int& TotalLen);

std::optional<Message> RecvMessages(const SOCKET& SocketHandle,const ReceiverTypes& RecvType);