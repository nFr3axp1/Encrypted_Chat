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
#include <chrono>
#include <string>
#include <ThreadsPool.h>
#include<NetIO.h>

#define PORT 9090

static std::vector<std::shared_ptr<SocketGuard>> ClientSockets;//管理所有SOCKET指针
static std::unordered_map<std::shared_ptr<SocketGuard>,uint32_t> ClientSocket_ptrToID_Map;//通过SocketGuard指针查找对应的用户ID
static std::unordered_map<uint32_t,std::shared_ptr<SocketGuard>> IDToClientSocket_ptr_Map;//通过用户ID查找对应SocketGuard指针
static std::mutex ClientSocketsAndIDMapMutex;//对2个Map变量的锁
static std::mutex ClientSocketsMutex;//对ClientSockets的锁

struct Probe {
    bool ProbeStatus;
    bool ProbeReplyStatus;
    std::chrono::steady_clock::time_point StartedPoint;
};
static uint32_t ProbeWaitingTime=300;//单位ms
static uint32_t ProbeTimeout=800;//单位ms
static std::unordered_map<std::shared_ptr<SocketGuard>,Probe> Socket_To_Got_Probe_Reply_Status_Map;
static std::mutex ProbeMutex;

static std::mutex IOMutex;//对cout和cin的锁

static ThreadsPool& MyThreadsPool=ThreadsPool::InitThreadPool(10);//线程池


static bool SendMessagesToClient(const std::shared_ptr<SocketGuard> ClientSocket,const uint32_t& ServerMsgType) {
    Message ServerMessage;
    ServerMessage.UserIDSender=0;

    std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);
    if (const auto ClientIDIterator = ClientSocket_ptrToID_Map.find(ClientSocket);
        ClientIDIterator != ClientSocket_ptrToID_Map.end()) {
            ServerMessage.UserIDReceiver=ClientIDIterator->second;
        }
    lock.unlock();

    ServerMessage.SenderType=static_cast<uint32_t>(SenderTypes::Server);
    ServerMessage.MessageType=ServerMsgType;
    auto[pkg,len]=ConvertMessagesToNetStream(ServerMessage);

    if (SendMessages(*ClientSocket,pkg.data(),len)) {//调用发送消息函数
        std::unique_lock<std::mutex> IOlock(IOMutex);
        std::cout<<"Send message successfully"<<std::endl;
        return true;
    }else {
        std::unique_lock<std::mutex> IOlock(IOMutex);
        std::cout<<"Send message failed:"<<WSAGetLastError()<<std::endl;
        return false;
    }
}
static bool ForwardMessagesToTarget(const std::shared_ptr<SocketGuard> TargetSocket,const Message& ClientMsg) {
    Message ForwardMessage;
    ForwardMessage.UserIDSender=ClientMsg.UserIDSender;

    ForwardMessage.UserIDReceiver=ClientMsg.UserIDReceiver;

    ForwardMessage.SenderType=static_cast<uint32_t>(SenderTypes::Server);
    ForwardMessage.MessageType=static_cast<uint32_t>(ServerMessageTypes::Forward);
    ForwardMessage.TextMessage=ClientMsg.TextMessage;
    auto[pkg,len]=ConvertMessagesToNetStream(ForwardMessage);

    if (SendMessages(*TargetSocket,pkg.data(),len)) {//调用发送消息函数
        std::unique_lock<std::mutex> IOlock(IOMutex);
        std::cout<<"Forward message successfully"<<std::endl;
        return true;
    }else {
        std::unique_lock<std::mutex> IOlock(IOMutex);
        std::cout<<"Forward message failed:"<<WSAGetLastError()<<std::endl;
        return false;
    }
}

static bool ProbeThread() {
    while (!MyThreadsPool.StopSource.stop_requested()) {
        std::vector<std::shared_ptr<SocketGuard>> Snapshot;
        {
            std::unique_lock<std::mutex> ClientSocketslock(ClientSocketsMutex);
            Snapshot=ClientSockets;
        }

        for (auto& i:Snapshot) {
            bool ShouldSend=false;
            {
                std::unique_lock<std::mutex> Probelock(ProbeMutex);
                if (const auto ProbeReplyIterator=Socket_To_Got_Probe_Reply_Status_Map.find(i);
                    ProbeReplyIterator!=Socket_To_Got_Probe_Reply_Status_Map.end()) {//找到Socket对应的Probe信息

                    if (ProbeReplyIterator->second.ProbeStatus==false) {//还没发包
                        ShouldSend=true;//在底下正式发包,防止死锁
                        ProbeReplyIterator->second.ProbeStatus=true;
                        ProbeReplyIterator->second.ProbeReplyStatus=false;
                        ProbeReplyIterator->second.StartedPoint=std::chrono::steady_clock::now();
                    }
                    else {//已经发包,等待回复
                        if (ProbeReplyIterator->second.ProbeReplyStatus==false) {//未回复
                            auto Now=std::chrono::steady_clock::now();
                            auto Duration=Now-ProbeReplyIterator->second.StartedPoint;
                            if (Duration>std::chrono::milliseconds(ProbeTimeout)) {//超时
                                i->CloseSocketHandle();
                                std::unique_lock<std::mutex> IOlock(IOMutex);
                                std::cout<<"Socket Timeout,Closing the Socket"<<std::endl;
                            }else {//未超时
                                continue;
                            }
                        }
                        else {//已回复
                            ProbeReplyIterator->second.ProbeStatus=false;
                            ProbeReplyIterator->second.ProbeReplyStatus=false;
                            continue;
                        }
                    }
                    }
                else {//没找到SOCKET对应的Probe信息
                    std::unique_lock<std::mutex> IOlock(IOMutex);
                    std::cout<<"Haven't found Probe information,Closing the Socket"<<std::endl;
                    continue;
                }
            }
            if (ShouldSend&&!SendMessagesToClient(i,static_cast<uint32_t>(ServerMessageTypes::Probe))) {//发包失败
                i->CloseSocketHandle();
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Probe Package Haven't be Sent,Closing the Socket"<<std::endl;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(ProbeWaitingTime));
    }
    return true;
}

static bool ForwardMessagesThread(std::shared_ptr<SocketGuard> ClientSocket) {
    std::stop_callback unblock{MyThreadsPool.StopSource.get_token(),[&]() {
        ClientSocket->CloseSocketHandle();
    }};

    //客户端关闭时调用的清理函数
    auto CloseSocket=[&]() {
        std::unique_lock<std::mutex> Maplock(ClientSocketsAndIDMapMutex);
        std::unique_lock<std::mutex> ClientsSocketlock(ClientSocketsMutex);
        std::unique_lock<std::mutex> Probelock(ProbeMutex);

        //清除服务器存储的客户端信息
        uint32_t ClientID = 0;
        if (const auto ClientIDIterator = ClientSocket_ptrToID_Map.find(ClientSocket);
            ClientIDIterator != ClientSocket_ptrToID_Map.end()) {
                std::erase(ClientSockets,ClientSocket);          // 删 vector成员
                ClientID = ClientIDIterator->second;
                ClientSocket_ptrToID_Map.erase(ClientIDIterator);//清除Socket指针到ID的表
                Socket_To_Got_Probe_Reply_Status_Map.erase(ClientSocket);//清除Socket到Probe状态的表
            }
        if (ClientID != 0) {
            IDToClientSocket_ptr_Map.erase(ClientID);//清除ID到Socket指针的表
        }
        ClientSocket->CloseSocketHandle();
    };

    while (!MyThreadsPool.StopSource.stop_requested()) {
        auto OptMessageJudging = RecvMessages(ClientSocket->SocketHandle,ReceiverTypes::Server);//阻塞接收
        if (OptMessageJudging==std::nullopt) {
            CloseSocket();
            std::unique_lock<std::mutex> IOlock(IOMutex);
            if (MyThreadsPool.StopSource.stop_requested()) {
                std::cout<<"Server Shutting Down"<<std::endl;
            }else {
                std::cout<<"Client disconnected unexpectedly"<<std::endl;
            }
            return false;
        }

        if (OptMessageJudging.value().SenderType==static_cast<uint32_t>(SenderTypes::Client)) {
            //安全退出
            if (OptMessageJudging.value().MessageType==static_cast<uint32_t>(ClientMessageTypes::ClientSafeQuit)) {
                CloseSocket();
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Client Quit Safely"<<std::endl;
                return true;
            }else if (OptMessageJudging.value().MessageType==static_cast<uint32_t>(ClientMessageTypes::ClientErrorQuit)) {
                CloseSocket();
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Client Quit Wrongly"<<std::endl;
                return false;
            }
            //检测心跳包
            else if (OptMessageJudging.value().MessageType==static_cast<uint32_t>(ClientMessageTypes::ReplyProbe)) {
                std::unique_lock<std::mutex> Probelock(ProbeMutex);
                Socket_To_Got_Probe_Reply_Status_Map[ClientSocket].ProbeReplyStatus=true;
                Probelock.unlock();
                continue;
            }
            const Message& getMessage=OptMessageJudging.value();
            //检测登录合法性
            if (getMessage.MessageType==static_cast<uint32_t>(ClientMessageTypes::Login)) {
                std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);
                if (getMessage.UserIDSender==0) {
                    lock.unlock();
                    SendMessagesToClient(ClientSocket,static_cast<uint32_t>(ServerMessageTypes::LoginFailedToken_IDis0));
                    std::unique_lock<std::mutex> IOlock(IOMutex);
                    std::cout<<"Login Failed,ID can't be 0!"<<std::endl;
                }
                else if (const auto SelfIDIterator=ClientSocket_ptrToID_Map.find(ClientSocket);
                    SelfIDIterator!=ClientSocket_ptrToID_Map.end() && SelfIDIterator->second!=0){//ID已被使用(本机重复登陆)
                        lock.unlock();
                        SendMessagesToClient(ClientSocket,static_cast<uint32_t>(ServerMessageTypes::LoginFailedToken_UsedID));
                        std::unique_lock<std::mutex> IOlock(IOMutex);
                        std::cout<<"Login Failed,ID have been used!"<<std::endl;
                    }
                else if (IDToClientSocket_ptr_Map.contains(getMessage.UserIDSender)) {//ID已被使用
                    lock.unlock();
                    SendMessagesToClient(ClientSocket,static_cast<uint32_t>(ServerMessageTypes::LoginFailedToken_UsedID));
                    std::unique_lock<std::mutex> IOlock(IOMutex);
                    std::cout<<"Login Failed,ID have been used!"<<std::endl;
                }
                else {//合法登陆ID
                    ClientSocket_ptrToID_Map[ClientSocket]=getMessage.UserIDSender;
                    IDToClientSocket_ptr_Map[getMessage.UserIDSender]=ClientSocket;
                    lock.unlock();
                    SendMessagesToClient(ClientSocket,static_cast<uint32_t>(ServerMessageTypes::LoginSuccessfulToken));
                    std::unique_lock<std::mutex> IOlock(IOMutex);
                    std::cout<<"Login successfully!!!"<<std::endl;
                }
            }
            //检测目标ID合法性
            else if (getMessage.MessageType==static_cast<uint32_t>(ClientMessageTypes::CheckID)) {
                uint32_t TargetUserID=getMessage.UserIDReceiver;
                if (TargetUserID==0) {
                    SendMessagesToClient(ClientSocket,static_cast<uint32_t>(ServerMessageTypes::IllegalTargetID_IDis0));
                    std::unique_lock<std::mutex> IOlock(IOMutex);
                    std::cout<<"Target User ID can't be 0!"<<std::endl;
                    continue;
                }

                std::unique_lock<std::mutex> lock(ClientSocketsAndIDMapMutex);

                std::shared_ptr<SocketGuard> TargetSocket=nullptr;
                if (const auto TargetSocketIterator = IDToClientSocket_ptr_Map.find(getMessage.UserIDReceiver);
                TargetSocketIterator != IDToClientSocket_ptr_Map.end()) {
                    TargetSocket = TargetSocketIterator->second;
                }
                if (TargetUserID!=0 && TargetSocket!=nullptr) {//键存在
                    if (TargetSocket !=ClientSocket) {
                        lock.unlock();
                        SendMessagesToClient(ClientSocket,static_cast<uint32_t>(ServerMessageTypes::LegalTargetID));
                        std::unique_lock<std::mutex> IOlock(IOMutex);
                        std::cout<<"Target User ID is Legal"<<std::endl;
                    }else {
                        lock.unlock();
                        SendMessagesToClient(ClientSocket,static_cast<uint32_t>(ServerMessageTypes::IllegalTargetID_TargetSelf));
                        std::unique_lock<std::mutex> IOlock(IOMutex);
                        std::cout<<"Target User ID can't be self!"<<std::endl;
                    }
                }
                else{
                    lock.unlock();
                    SendMessagesToClient(ClientSocket,static_cast<uint32_t>(ServerMessageTypes::IllegalTargetID_Invalid));
                    std::unique_lock<std::mutex> IOlock(IOMutex);
                    std::cout<<"Target is Missing!"<<std::endl;
                }
            }
            //检测发送消息的合法性
            else if (getMessage.MessageType==static_cast<uint32_t>(ClientMessageTypes::Normal)) {
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
                    SendMessagesToClient(ClientSocket,static_cast<uint32_t>(ServerMessageTypes::ForwardFailed));
                    std::cout<<"Target "<<TargetUserID<<" is offline, message dropped"<<std::endl;
                    continue;
                }else {
                    ForwardMessagesToTarget(TargetSocket,getMessage);
                    //通知发送端发送成功
                    SendMessagesToClient(ClientSocket,static_cast<uint32_t>(ServerMessageTypes::ForwardSuccessfully));
                    std::unique_lock<std::mutex> IOlock(IOMutex);
                    std::cout<<"Forward message successfully!"<<std::endl;
                }
            }
            //其他异常的消息
            else {
                SendMessagesToClient(ClientSocket,static_cast<uint32_t>(ServerMessageTypes::ForwardFailed));
                CloseSocket();
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<"Forward message failed:"<<WSAGetLastError()<<std::endl;
                return false;
            }
        }
        else {
            SendMessagesToClient(ClientSocket,static_cast<uint32_t>(ServerMessageTypes::ForwardFailed));
            CloseSocket();
            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<"Unexpected SenderType, connection closed"<<std::endl;
            return false;
        }
    }
    return true;
}

static void AcceptThread(const SocketGuard& ListeningSocket) {
    while (!MyThreadsPool.StopSource.stop_requested()) {
        auto ClientSocket=std::make_shared<SocketGuard>();

        ClientSocket->SocketHandle=accept(ListeningSocket.SocketHandle, nullptr,nullptr);

        if (!IsOK(JudgeType::SocketAccept,static_cast<int>(ClientSocket->SocketHandle))) {
            return;
        }
        else {
            //保存客户端信息
            std::unique_lock<std::mutex> Maplock(ClientSocketsAndIDMapMutex);
            std::unique_lock<std::mutex> ClientSocketlock(ClientSocketsMutex);
            std::unique_lock<std::mutex> Probelock(ProbeMutex);
            ClientSockets.push_back(std::move(ClientSocket));//存SOCKETGUARD指针

            ClientSocket_ptrToID_Map[ClientSockets.back()]=0;//给当前客户端占位,等待ID到达后填入

            MyThreadsPool.AddTask(ForwardMessagesThread,ClientSockets.back());//开启转发线程

            Socket_To_Got_Probe_Reply_Status_Map[ClientSockets.back()].ProbeStatus=false;//初始Probe状态
            Socket_To_Got_Probe_Reply_Status_Map[ClientSockets.back()].ProbeReplyStatus=false;//初始Probe状态

            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<"Client accepted successfully,handle id:"<<ClientSockets.back()->SocketHandle<<std::endl;
        }
    }
    return;
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

    result = ::bind(ListeningSocket.SocketHandle,reinterpret_cast<sockaddr*>(&ListeningSocket.SocketHandleAddr) , sizeof(ListeningSocket.SocketHandleAddr));
    if (!IsOK(JudgeType::SocketBind,result)) {
        return 1;
    }

    result=listen(ListeningSocket.SocketHandle,SOMAXCONN);
    if (!IsOK(JudgeType::SocketListen,result)) {
        return 1;
    }

    MyThreadsPool.AddTask(AcceptThread,std::ref(ListeningSocket));
    MyThreadsPool.AddTask(ProbeThread);

    std::cin.get();
    ListeningSocket.CloseSocketHandle();
    MyThreadsPool.StopThreadsPool();
    return 0;
}