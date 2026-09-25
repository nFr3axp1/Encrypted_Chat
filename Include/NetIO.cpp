#include "NetIO.h"
#include<WinSock2.h>
#include<NetGuard.h>
#include<vector>
#include<tuple>
#include<iostream>
#include <optional>

std::tuple<std::vector<char>,int> ConvertMessagesToNetStream(const Message& message) {
    std::vector<char> Body;
    Body.insert(Body.end(),message.TextMessage.begin(),message.TextMessage.end());

    std::vector<char>Package;
    uint32_t NetMessageType=htonl(message.MessageType);
    Package.insert(Package.end(),reinterpret_cast<char *>(&NetMessageType),reinterpret_cast<char *>(&NetMessageType)+4);

    uint32_t NetBodyLength=htonl(Body.size());
    Package.insert(Package.end(),reinterpret_cast<char *>(&NetBodyLength),reinterpret_cast<char *>(&NetBodyLength)+4);

    uint32_t NetUserIDSender=htonl(message.UserIDSender);
    Package.insert(Package.end(),reinterpret_cast<char *>(&NetUserIDSender),reinterpret_cast<char *>(&NetUserIDSender)+4);

    uint32_t NetUserIDRecv=htonl(message.UserIDReceiver);
    Package.insert(Package.end(),reinterpret_cast<char *>(&NetUserIDRecv),reinterpret_cast<char *>(&NetUserIDRecv)+4);

    Package.insert(Package.end(),Body.begin(),Body.end());

    return std::make_tuple(Package,Package.size());
};

bool SendMessages(const SOCKET& SocketHandle,const char* MessagesNetStreamHead_ptr,const int& TotalLen) {
    int HaveSendedSize=0;
    int CurrentSendedSize=0;
    while (true) {
        CurrentSendedSize=send(SocketHandle,MessagesNetStreamHead_ptr+HaveSendedSize,TotalLen-HaveSendedSize,0);
        if (CurrentSendedSize<0) {
            return false;
        }
        else if (CurrentSendedSize==0) {
            return true;
        }
        HaveSendedSize+=CurrentSendedSize;
        if (HaveSendedSize==TotalLen) {
            return true;
        }
    }
    return false;
}


std::optional<Message> RecvMessages(const SOCKET& ClientSocketHandle) {
    Message RtMessage;

    constexpr int HeadBytes=4*Message::HeadNum;
    char RecvMessagesHead[HeadBytes];
    int HaveRecvedSize=0;

    while (true) {
        int CurrentRecvedSize=recv(ClientSocketHandle,RecvMessagesHead+HaveRecvedSize,HeadBytes-HaveRecvedSize,0);
        if (CurrentRecvedSize<0) {//发生错误
            return std::nullopt;
        }
        if (CurrentRecvedSize==0) {//优雅推出
            RtMessage.MessageType=static_cast<uint32_t>(MessageType::ClientSafeQuit);
            return RtMessage;
        }
        HaveRecvedSize+=CurrentRecvedSize;
        if (HaveRecvedSize==HeadBytes) {//接收完毕
            break;
        }
    }

    for (char& i : RecvMessagesHead) {//把原始流头部加入Raw，方便转发
        RtMessage.RawMessageNetStream+=i;
    }

    //读取网络消息流头信息
    uint32_t RecvMessagesType=ntohl(*reinterpret_cast<uint32_t*>(RecvMessagesHead));
    uint32_t RecvMessagesHead_BodySize_HOST=ntohl(*reinterpret_cast<uint32_t*>(RecvMessagesHead+4));
    uint32_t RecvMessagesHead_Sender_HOST=ntohl(*reinterpret_cast<uint32_t*>(RecvMessagesHead+8));
    uint32_t RecvMessagesHead_Receiver_HOST=ntohl(*reinterpret_cast<uint32_t*>(RecvMessagesHead+12));

    RtMessage.UserIDSender=RecvMessagesHead_Sender_HOST;
    RtMessage.UserIDReceiver=RecvMessagesHead_Receiver_HOST;

    std::vector<char>RecvMessagesBody;
    RecvMessagesBody.resize(RecvMessagesHead_BodySize_HOST);
    HaveRecvedSize=0;
    if (RecvMessagesHead_BodySize_HOST>0) {
        while (true) {
            int CurrentRecvedSize=recv(ClientSocketHandle,RecvMessagesBody.data()+HaveRecvedSize,static_cast<int>(RecvMessagesHead_BodySize_HOST)-HaveRecvedSize,0);
            if (CurrentRecvedSize<0) {//发生错误
                return std::nullopt;
            }
            if (CurrentRecvedSize==0) {
                break;
            }
            HaveRecvedSize+=CurrentRecvedSize;
            if (HaveRecvedSize==RecvMessagesHead_BodySize_HOST) {
                break;
            }
        }
    }

    for (auto& i : RecvMessagesBody) {
        RtMessage.TextMessage.push_back(i);//把文本消息内容加入TextMessage
    }

    RtMessage.RawMessageNetStream+=RtMessage.TextMessage;//把文本消息内容加入Raw，方便转发

    //设置发送的Message包类型
    if (RecvMessagesType!=static_cast<uint32_t>(MessageType::Error)) {
        RtMessage.MessageType=RecvMessagesType;
    }
    else {
        RtMessage.MessageType=static_cast<uint32_t>(MessageType::Error);
    }
    return RtMessage;
}