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

static std::vector<std::shared_ptr<SocketGuard>> ClientSockets;//管理SOCKET实例
static std::unordered_map<SOCKET,std::shared_ptr<SocketGuard>>SocketHandleToSocketGuard_ptr_Map;//通过Socket找到SocketGuard的指针
static std::unordered_map<SOCKET,uint32_t> ClientSocketHandle_ptrToID_Map;//通过SOCKET查找对应的用户ID
static std::unordered_map<uint32_t,SOCKET> IDToClientSocketHandle_ptr_Map;//通过用户ID查找对应SOCKET
static std::mutex ClientSocketsAndIDMapMutex;//对三个变量的锁

static std::mutex IOMutex;

static std::mutex ClientSocketsMutex;
static ThreadsPool& MyThreadsPool=ThreadsPool::InitThreadPool(10);


static void SendMessagesToClient(const SOCKET& ClientSocketHandle,const std::string& msg) {
    Message WarnMessage;
    WarnMessage.UserIDSender=0;

    std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);
    WarnMessage.UserIDReceiver=ClientSocketHandle_ptrToID_Map[ClientSocketHandle];
    lock.unlock();

    WarnMessage.MessageType=static_cast<uint32_t>(MessageType::Server);
    WarnMessage.TextMessage=msg;
    auto[pkg,len]=ConvertMessagesToNetStream(WarnMessage);

    if (SendMessages(ClientSocketHandle,pkg.data(),len)) {//调用发送消息函数
        std::unique_lock<std::mutex> IOlock(IOMutex);
        std::cout<<"Send message successfully"<<std::endl;
    }else {
        std::unique_lock<std::mutex> IOlock(IOMutex);
        std::cout<<"Send message failed:"<<WSAGetLastError()<<std::endl;
    }
}

static bool ForwardMessagesThread(SOCKET& ClientSocketHandle) {
    std::stop_callback unblock{MyThreadsPool.StopSource.get_token(),[&]() {
        SocketHandleToSocketGuard_ptr_Map[ClientSocketHandle]->CloseSocketHandle();
    }};
    while (true) {
        auto OptMessageJudging = RecvMessages(std::ref(ClientSocketHandle));
        if (OptMessageJudging==std::nullopt) {
            return false;
        }
        //安全退出
        if (OptMessageJudging.value().MessageType==static_cast<uint32_t>(MessageType::ClientSafeQuit)) {
            std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);
            //关闭对应SOCKET
            SocketHandleToSocketGuard_ptr_Map[ClientSocketHandle]->CloseSocketHandle();
            //清除服务器存储的客户端信息
            std::erase(ClientSockets,SocketHandleToSocketGuard_ptr_Map[ClientSocketHandle]);
            SocketHandleToSocketGuard_ptr_Map.erase(ClientSocketHandle);
            ClientSocketHandle_ptrToID_Map.erase(ClientSocketHandle);
            IDToClientSocketHandle_ptr_Map.erase(ClientSocketHandle_ptrToID_Map[ClientSocketHandle]);
            lock.unlock();
            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<"Client Safe Quit"<<std::endl;
            return true;
        }

        const Message& getMessage=OptMessageJudging.value();
        //检测登录合法性
        if (getMessage.MessageType==static_cast<uint32_t>(MessageType::Login)) {
            std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);
            if (IDToClientSocketHandle_ptr_Map.contains(getMessage.UserIDSender)) {
                lock.unlock();
                SendMessagesToClient(std::ref(ClientSocketHandle),Message::LoginFailedToken_UsedID);
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Login Failed!"<<std::endl;
            }
            else {
                ClientSocketHandle_ptrToID_Map[ClientSocketHandle]=getMessage.UserIDSender;
                IDToClientSocketHandle_ptr_Map[getMessage.UserIDSender]=ClientSocketHandle;
                lock.unlock();
                SendMessagesToClient(std::ref(ClientSocketHandle),Message::LoginSuccessfulToken);
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Login successfully!!!"<<std::endl;
            }
        }
        //检测目标ID合法性
        else if (getMessage.MessageType==static_cast<uint32_t>(MessageType::CheckID)) {
            uint32_t TargetUserID=getMessage.UserIDReceiver;

            if (TargetUserID==0) {
                SendMessagesToClient(std::ref(ClientSocketHandle),Message::IDIllegal_IDis0);
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Target User ID can't be 0!"<<std::endl;
            }

            std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);
            if (TargetUserID!=0 && IDToClientSocketHandle_ptr_Map.contains(TargetUserID)) {//键存在
                if (IDToClientSocketHandle_ptr_Map[getMessage.UserIDReceiver]!=ClientSocketHandle) {
                    lock.unlock();
                    SendMessagesToClient(std::ref(ClientSocketHandle),Message::IDLegal);
                    std::unique_lock<std::mutex> IOlock(IOMutex);
                    std::cout<<"Target User ID is Legal"<<std::endl;
                }else {
                    lock.unlock();
                    SendMessagesToClient(std::ref(ClientSocketHandle),Message::IDIllegal_TargetSelf);
                    std::unique_lock<std::mutex> IOlock(IOMutex);
                    std::cout<<"Target User ID can't be self!"<<std::endl;
                }
            }
            else{
                lock.unlock();
                SendMessagesToClient(std::ref(ClientSocketHandle),Message::IDIllegal_Invalid);
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Target is Missing!"<<std::endl;
            }
        }
        //检测发送消息的合法性
        else if (getMessage.MessageType==static_cast<uint32_t>(MessageType::Normal)) {
            //发送消息给接收端
            std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);
            uint32_t TargetUserID=getMessage.UserIDReceiver;
            auto TargetSocketHandle=IDToClientSocketHandle_ptr_Map[TargetUserID];
            lock.unlock();
            SendMessages(TargetSocketHandle,getMessage.RawMessageNetStream.c_str(),static_cast<int>(getMessage.RawMessageNetStream.size()));

            //通知发送端发送成功
            SendMessagesToClient(std::ref(ClientSocketHandle),Message::SendSuccessfully);
            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<"Forward message successfully!"<<std::endl;
        }
        //其他异常消息
        else {
            SendMessagesToClient(std::ref(ClientSocketHandle),Message::SendFailed);
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
                {
                    std::unique_lock<std::mutex> ClientSocketlock(ClientSocketsMutex);
                    ClientSockets.push_back(std::move(ClientSocket));

                    std::unique_lock<std::mutex> Maplock(ClientSocketsAndIDMapMutex);
                    SocketHandleToSocketGuard_ptr_Map[ClientSockets.back()->SocketHandle]=ClientSockets.back();//把Socket对应的指针存入
                    ClientSocketHandle_ptrToID_Map[ClientSockets.back()->SocketHandle]=0;
                    MyThreadsPool.AddTask(ForwardMessagesThread,std::ref(ClientSockets.back()->SocketHandle));
                }

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