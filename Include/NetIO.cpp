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
    uint32_t NetSenderType=htonl(message.SenderType);//服务端发包还是客户端发包
    Package.insert(Package.end(),reinterpret_cast<char *>(&NetSenderType),reinterpret_cast<char *>(&NetSenderType)+4);

    uint32_t NetMessageType=htonl(message.MessageType);//消息类型(具体的消息种类)
    Package.insert(Package.end(),reinterpret_cast<char *>(&NetMessageType),reinterpret_cast<char *>(&NetMessageType)+4);

    uint32_t NetUserIDSender=htonl(message.UserIDSender);//发送者ID
    Package.insert(Package.end(),reinterpret_cast<char *>(&NetUserIDSender),reinterpret_cast<char *>(&NetUserIDSender)+4);

    uint32_t NetUserIDRecv=htonl(message.UserIDReceiver);//接受者ID
    Package.insert(Package.end(),reinterpret_cast<char *>(&NetUserIDRecv),reinterpret_cast<char *>(&NetUserIDRecv)+4);

    uint32_t NetBodyLength=htonl(Body.size());//消息内容长度(不含头)
    Package.insert(Package.end(),reinterpret_cast<char *>(&NetBodyLength),reinterpret_cast<char *>(&NetBodyLength)+4);

    Package.insert(Package.end(),Body.begin(),Body.end());//消息内容

    return std::make_tuple(Package,Package.size());
};

static bool SendMessagesWithoutLock(const SOCKET& SocketHandle,const char* MessagesNetStreamHead_ptr,const int& TotalLen) {
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
bool SendMessages(SocketGuard& Socket,const char* MessagesNetStreamHead_ptr,const int& TotalLen) {
    std::unique_lock<std::mutex>Sendlock(Socket.SendMutex);
    return SendMessagesWithoutLock(Socket.SocketHandle,MessagesNetStreamHead_ptr,TotalLen);
}

std::optional<Message> RecvMessages(const SOCKET& SocketHandle,const ReceiverTypes& ReceiverType) {
    Message RtMessage;

    constexpr int HeadBytes=4*Message::HeadNum;
    char RecvMessagesHead[HeadBytes];
    int HaveRecvedSize=0;

    //接受头
    while (true) {
        int CurrentRecvedSize=recv(SocketHandle,RecvMessagesHead+HaveRecvedSize,HeadBytes-HaveRecvedSize,0);
        if (CurrentRecvedSize<0) {//发生错误
            return std::nullopt;
        }
        if (CurrentRecvedSize==0) {//优雅推出
            if (ReceiverType==ReceiverTypes::Server) {//接收端是服务器时
                RtMessage.SenderType=static_cast<uint32_t>(SenderTypes::Client);
                RtMessage.MessageType=static_cast<uint32_t>(ClientMessageTypes::ClientSafeQuit);
                return RtMessage;
            }else if (ReceiverType==ReceiverTypes::Client) {//接收端是客户端时
                RtMessage.SenderType=static_cast<uint32_t>(SenderTypes::Server);
                RtMessage.MessageType=static_cast<uint32_t>(ServerMessageTypes::ServerSafeQuit);
                return RtMessage;
            }else {
                return std::nullopt;
            }
        }
        HaveRecvedSize+=CurrentRecvedSize;
        if (HaveRecvedSize==HeadBytes) {//接收完毕
            break;
        }
    }

    //读取网络消息流头信息
    /*SenderType_
     * MessageType
     * SenderID
     * ReceiverID
     * ContentLen
     * Content
     */
    uint32_t RecvMessagesHead_SenderType_HOST=ntohl(*reinterpret_cast<uint32_t*>(RecvMessagesHead));
    uint32_t RecvMessagesHead_MsgType_HOST=ntohl(*reinterpret_cast<uint32_t*>(RecvMessagesHead+4));
    uint32_t RecvMessagesHead_SenderID_HOST=ntohl(*reinterpret_cast<uint32_t*>(RecvMessagesHead+8));
    uint32_t RecvMessagesHead_ReceiverID_HOST=ntohl(*reinterpret_cast<uint32_t*>(RecvMessagesHead+12));
    uint32_t RecvMessagesHead_BodySize_HOST=ntohl(*reinterpret_cast<uint32_t*>(RecvMessagesHead+16));

    //设置头
    RtMessage.SenderType=RecvMessagesHead_SenderType_HOST;
    RtMessage.MessageType=RecvMessagesHead_MsgType_HOST;
    RtMessage.UserIDSender=RecvMessagesHead_SenderID_HOST;
    RtMessage.UserIDReceiver=RecvMessagesHead_ReceiverID_HOST;

    //设置内容
    std::vector<char>RecvMessagesBody;
    RecvMessagesBody.resize(RecvMessagesHead_BodySize_HOST);
    HaveRecvedSize=0;
    if (RecvMessagesHead_BodySize_HOST>0) {
        while (true) {
            int CurrentRecvedSize=recv(SocketHandle,RecvMessagesBody.data()+HaveRecvedSize,static_cast<int>(RecvMessagesHead_BodySize_HOST)-HaveRecvedSize,0);
            if (CurrentRecvedSize<=0) {//发生错误
                return std::nullopt;
            }
            HaveRecvedSize+=CurrentRecvedSize;
            if (HaveRecvedSize==RecvMessagesHead_BodySize_HOST) {
                break;
            }
        }
        for (auto& i : RecvMessagesBody) {
            RtMessage.TextMessage.push_back(i);//把文本消息内容加入TextMessage
        }
    }

    //返回Message
    return RtMessage;
}