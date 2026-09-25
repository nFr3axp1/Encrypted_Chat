#include<iostream>
#include<WinSock2.h>
#include<ws2tcpip.h>
#include<windows.h>
#include<NetGuard.h>
#include<Log.h>
#include<mutex>
#include<thread>
#include<future>
#include<condition_variable>
#include<queue>
#include<functional>
#include<type_traits>
#include<memory>
#include<vector>
#include<atomic>
#include <string>
#include <ThreadsPool.h>
#include<NetIO.h>

#define PORT 9090

static std::vector<std::shared_ptr<SocketGuard>> ClientSockets;//管理所有SOCKET指针
static std::unordered_map<std::shared_ptr<SocketGuard>,uint32_t> ClientSocket_ptrToID_Map;//通过SocketGuard指针查找对应的用户ID
static std::unordered_map<uint32_t,std::shared_ptr<SocketGuard>> IDToClientSocket_ptr_Map;//通过用户ID查找对应SocketGuard指针
static std::mutex ClientSocketsAndIDMapMutex;//对2个Map变量的锁
static std::mutex ClientSocketsMutex;//对ClientSockets的锁

static std::mutex IOMutex;


static ThreadsPool& MyThreadsPool=ThreadsPool::InitThreadPool(10);


static bool SendMessagesToClient(const std::shared_ptr<SocketGuard> ClientSocket,const std::string& msg) {
    Message WarnMessage;
    WarnMessage.UserIDSender=0;

    std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);
    WarnMessage.UserIDReceiver=ClientSocket_ptrToID_Map[ClientSocket];
    lock.unlock();

    WarnMessage.MessageType=static_cast<uint32_t>(MessageType::Server);
    WarnMessage.TextMessage=msg;
    auto[pkg,len]=ConvertMessagesToNetStream(WarnMessage);

    if (SendMessages(ClientSocket->SocketHandle,pkg.data(),len)) {//调用发送消息函数
        std::unique_lock<std::mutex> IOlock(IOMutex);
        std::cout<<"Send message successfully"<<std::endl;
        return true;
    }else {
        std::unique_lock<std::mutex> IOlock(IOMutex);
        std::cout<<"Send message failed:"<<WSAGetLastError()<<std::endl;
        return false;
    }
}

static bool ProbeThread(const std::shared_ptr<SocketGuard> ClientSocket) {
    while (true) {
        bool ClientStillAlive=SendMessagesToClient(ClientSocket,Message::ProbeMessage);
        if (ClientStillAlive==false) {

        }else {
            continue;
        }
    }
}

static bool ForwardMessagesThread(std::shared_ptr<SocketGuard> ClientSocket) {
    std::stop_callback unblock{MyThreadsPool.StopSource.get_token(),[&]() {
        ClientSocket->CloseSocketHandle();
    }};

    //客户端关闭时调用的清理函数
    auto CloseSocket=[&]() {
        std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);
        std::unique_lock<std::mutex> ClientsSocketlock(ClientSocketsMutex);

        //清除服务器存储的客户端信息
        uint32_t ClientID = 0;
        if (const auto ClientIDIterator = ClientSocket_ptrToID_Map.find(ClientSocket);
            ClientIDIterator != ClientSocket_ptrToID_Map.end()) {
                std::erase(ClientSockets,ClientSocket);          // 删 vector成员
                ClientID = ClientIDIterator->second;
                ClientSocket_ptrToID_Map.erase(ClientIDIterator);//清除Socket指针到ID的表
            }
        if (ClientID != 0) {
            IDToClientSocket_ptr_Map.erase(ClientID);//清除ID到Socket指针的表
        }
        ClientSocket->CloseSocketHandle();
        lock.unlock();
        ClientsSocketlock.unlock();
    };

    while (true) {
        auto OptMessageJudging = RecvMessages(std::ref(ClientSocket->SocketHandle));//阻塞接收
        if (OptMessageJudging==std::nullopt) {
            CloseSocket();
            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<"Client Error Quit"<<std::endl;
            return false;
        }
        //安全退出
        if (OptMessageJudging.value().MessageType==static_cast<uint32_t>(MessageType::ClientSafeQuit)) {
            CloseSocket();
            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<"Client Safe Quit"<<std::endl;
            return true;
        }

        const Message& getMessage=OptMessageJudging.value();
        //检测登录合法性
        if (getMessage.MessageType==static_cast<uint32_t>(MessageType::Login)) {
            std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);
            if (getMessage.UserIDSender==0) {
                lock.unlock();
                SendMessagesToClient(ClientSocket,Message::LoginFailedToken_IDis0);
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Login Failed,ID can't be 0!"<<std::endl;
            }
            else if (ClientSocket_ptrToID_Map[ClientSocket]!=0) {//ID已被使用(本机重复登陆)
                lock.unlock();
                SendMessagesToClient(ClientSocket,Message::LoginFailedToken_UsedID);
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Login Failed,ID have been used!"<<std::endl;
            }
            else if (IDToClientSocket_ptr_Map.contains(getMessage.UserIDSender)) {//ID已被使用
                lock.unlock();
                SendMessagesToClient(ClientSocket,Message::LoginFailedToken_UsedID);
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Login Failed,ID have been used!"<<std::endl;
            }
            else {//合法登陆ID
                ClientSocket_ptrToID_Map[ClientSocket]=getMessage.UserIDSender;
                IDToClientSocket_ptr_Map[getMessage.UserIDSender]=ClientSocket;
                lock.unlock();
                SendMessagesToClient(ClientSocket,Message::LoginSuccessfulToken);
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Login successfully!!!"<<std::endl;
            }
        }
        //检测目标ID合法性
        else if (getMessage.MessageType==static_cast<uint32_t>(MessageType::CheckID)) {
            uint32_t TargetUserID=getMessage.UserIDReceiver;
            if (TargetUserID==0) {
                SendMessagesToClient(ClientSocket,Message::IDIllegal_IDis0);
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Target User ID can't be 0!"<<std::endl;
            }
            std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);
            if (TargetUserID!=0 && IDToClientSocket_ptr_Map.contains(TargetUserID)) {//键存在
                if (IDToClientSocket_ptr_Map[getMessage.UserIDReceiver]!=ClientSocket) {
                    lock.unlock();
                    SendMessagesToClient(ClientSocket,Message::IDLegal);
                    std::unique_lock<std::mutex> IOlock(IOMutex);
                    std::cout<<"Target User ID is Legal"<<std::endl;
                }else {
                    lock.unlock();
                    SendMessagesToClient(ClientSocket,Message::IDIllegal_TargetSelf);
                    std::unique_lock<std::mutex> IOlock(IOMutex);
                    std::cout<<"Target User ID can't be self!"<<std::endl;
                }
            }
            else{
                lock.unlock();
                SendMessagesToClient(ClientSocket,Message::IDIllegal_Invalid);
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Target is Missing!"<<std::endl;
            }
        }
        //检测发送消息的合法性
        else if (getMessage.MessageType==static_cast<uint32_t>(MessageType::Normal)) {
            //发送消息给接收端
            std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);
            uint32_t TargetUserID=getMessage.UserIDReceiver;
            std::shared_ptr<SocketGuard> TargetSocket;
            const auto TargetIDIterator=IDToClientSocket_ptr_Map.find(TargetUserID);
            if (TargetIDIterator!=IDToClientSocket_ptr_Map.end()) {
                TargetSocket=TargetIDIterator->second;
            }
            lock.unlock();
            if (TargetSocket==nullptr) {
                SendMessagesToClient(ClientSocket,Message::SendFailed);
                std::cout<<"Target "<<TargetUserID<<" is offline, message dropped"<<std::endl;
                continue;
            }else {
                SendMessages(TargetSocket->SocketHandle,getMessage.RawMessageNetStream.c_str(),static_cast<int>(getMessage.RawMessageNetStream.size()));
                //通知发送端发送成功
                SendMessagesToClient(ClientSocket,Message::SendSuccessfully);
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Forward message successfully!"<<std::endl;
            }
        }
        //其他异常消息
        else {
            SendMessagesToClient(ClientSocket,Message::SendFailed);
            CloseSocket();
            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<"Forward message failed:"<<WSAGetLastError()<<std::endl;
            return false;
        }
    }
}

static void AcceptThread(const SocketGuard& ListeningSocket) {
    while (true) {
        auto ClientSocket=std::make_shared<SocketGuard>();

        ClientSocket->SocketHandle=accept(ListeningSocket.SocketHandle, nullptr,nullptr);

        if (!IsOK(JudgeType::SocketAccept,static_cast<int>(ClientSocket->SocketHandle))) {
            return;
        }
        else {
            //保存客户端信息
            std::unique_lock<std::mutex> Maplock(ClientSocketsAndIDMapMutex);
            std::unique_lock<std::mutex> ClientSocketlock(ClientSocketsMutex);
            ClientSockets.push_back(std::move(ClientSocket));//存SOCKETGUARD指针

            ClientSocket_ptrToID_Map[ClientSockets.back()]=0;//给当前客户端占位,等待ID到达后填入

            MyThreadsPool.AddTask(ForwardMessagesThread,ClientSockets.back());//开启转发线程

            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<"Client accepted successfully,handle id:"<<ClientSockets.back()->SocketHandle<<std::endl;
        }
    }
}

int main() {
    const WSAGuard wsaData;
    int result = 0;
    if (!IsOK(JudgeType::WSAStartUp,wsaData.CreatedMessage)) {
        return 1;
    }

    SocketGuard ListeningSocket{};
    ListeningSocket.SocketHandle=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ListeningSocket.SocketHandleAddr.sin_family = AF_INET;
    ListeningSocket.SocketHandleAddr.sin_port = htons(PORT);
    ListeningSocket.SocketHandleAddr.sin_addr.s_addr=INADDR_ANY;

    result = bind(ListeningSocket.SocketHandle,reinterpret_cast<sockaddr*>(&ListeningSocket.SocketHandleAddr) , sizeof(ListeningSocket.SocketHandleAddr));
    if (!IsOK(JudgeType::SocketBind,result)) {
        return 1;
    }

    result=listen(ListeningSocket.SocketHandle,SOMAXCONN);
    if (!IsOK(JudgeType::SocketListen,result)) {
        return 1;
    }

    MyThreadsPool.AddTask(AcceptThread,std::ref(ListeningSocket));

    std::cin.get();
    ListeningSocket.CloseSocketHandle();
    MyThreadsPool.StopThreadsPool();
    return 0;
}