#pragma once
#include<cstdint>
#include<tuple>
#include<vector>
#include<string>
#include<NetGuard.h>
#include<optional>

enum class MessageType {
    Server,Login,CheckID,Normal,ClientSafeQuit,ClientErrorQuit,Error,
    Probe,ProbeReply
};

struct Message {
    std::string TextMessage;

    uint32_t MessageType = static_cast<uint32_t>(MessageType::Login);
    uint32_t UserIDSender=0;
    uint32_t UserIDReceiver=0;

    std::string RawMessageNetStream;//原始网络流,方便转发

    static constexpr int HeadNum=4;//头参数数量

    //登陆关键词
    inline static const std::string LoginSuccessfulToken="Login Successfully!";
    inline static const std::string LoginFailedToken_IDis0="ID can't be 0";
    inline static const std::string LoginFailedToken_UsedID="This ID have been used!!";
    //ID检验关键词
    inline static const std::string IDLegal="ID is Legal";
    inline static const std::string IDIllegal_IDis0="ID can't be 0";
    inline static const std::string IDIllegal_Invalid="ID is Invalid";
    inline static const std::string IDIllegal_TargetSelf="ID can't be self";
    //发送消息关键词
    inline static const std::string SendSuccessfully="Send Successfully";
    inline static const std::string SendFailed="Send Failed";
    //探测包关键词
    inline static const std::string ProbeMessage="Server Probe";
};


std::tuple<std::vector<char>,int> ConvertMessagesToNetStream(const Message& message);
bool SendMessages(const SOCKET& SocketHandle,const char* MessagesNetStreamHead_ptr,const int& TotalLen);

std::optional<Message> RecvMessages(const SOCKET& ClientSocketHandle);