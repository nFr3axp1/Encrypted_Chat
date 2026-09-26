#include <iostream>
#include<WinSock2.h>
#include<ws2tcpip.h>
#include<windows.h>
#include<NetGuard.h>
#include<Log.h>

#include<string>
#include<vector>
#include<tuple>
#include<ThreadsPool.h>
#include<NetIO.h>
#include<condition_variable>
#include<limits>
#include<mutex>
#include<ClientIO.h>

#define IP "127.0.0.1"
#define PORT 9090

static ThreadsPool& MyThreadsPool=ThreadsPool::InitThreadPool(10);
static Message MyMessage{};

static bool HaveReplyLogged=false,HaveLogged=false;
static bool HaveJudgedID=false,IDLegal=false;

static std::mutex IOMutex,LoginMutex,IDJudgingMutex;
static std::condition_variable LoginCV,IDJudgingCV;


static void LoginRequest(SocketGuard& ConnectToServerSocket) {
    MyMessage.SenderType=static_cast<uint32_t>(SenderTypes::Client);
    MyMessage.MessageType=static_cast<uint32_t>(ClientMessageTypes::Login);
    MyMessage.UserIDReceiver=0;

    auto [pkg,len]=ConvertMessagesToNetStream(MyMessage);//将消息转换为网络字节流
    SendMessages(ConnectToServerSocket,pkg.data(),len); //调用发送消息函数
}

static bool WaitingLoginReply() {
    while (true) {
        std::unique_lock<std::mutex> Loginlock(LoginMutex);
        LoginCV.wait(Loginlock,[]() {
            return HaveReplyLogged;
        });
        HaveReplyLogged=false;
        return HaveLogged;
    }
}

static bool WaitingIDJudging() {
    while (true) {
        std::unique_lock<std::mutex> IDJudginglock(IDJudgingMutex);
        IDJudgingCV.wait(IDJudginglock,[]() {
            return HaveJudgedID;
        });
        HaveJudgedID=false;
        return IDLegal;
    }
}

static bool SendMessagesThread(SocketGuard& ConnectToServerSocket) {//正常关闭返回true
    while (true) {
        MyMessage.SenderType=static_cast<uint32_t>(SenderTypes::Client);
        MyMessage.MessageType=static_cast<uint32_t>(ClientMessageTypes::CheckID);
        //输入目标用户ID
        while (true) {
            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<"Input Target User ID: ";
            IOlock.unlock();

            CinRtStatus GetCinRtStatuts=InputCheck(MyMessage.UserIDReceiver);
            if (GetCinRtStatuts==CinRtStatus::Legal) {
                //迁移ID判断到服务端
                break;
            }else if (GetCinRtStatuts==CinRtStatus::Illegal) {
                IOlock.lock();
                std::cout<<"Illegal Input!"<<std::endl;
                IOlock.unlock();
            }else {
                return false;
            }
        }
        //检测ID合法性
        auto [pkg_only_id,len_only_id]=ConvertMessagesToNetStream(MyMessage);//将消息转换为网络字节流
        SendMessages(ConnectToServerSocket,pkg_only_id.data(),len_only_id);//调用发送消息函数

        auto IDJudgingResult=MyThreadsPool.AddTask(WaitingIDJudging);
        if (IDJudgingResult.get()) {//ID合法
            MyMessage.SenderType=static_cast<uint32_t>(SenderTypes::Client);
            MyMessage.MessageType=static_cast<uint32_t>(ClientMessageTypes::Normal);
            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<"Send Message:";
            IOlock.unlock();

            //输入Text字符串
            std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
            if (!std::getline(std::cin, MyMessage.TextMessage)) {// 处理输入流失效
                return false;
            }

            if (MyMessage.TextMessage=="quit") {
                shutdown(ConnectToServerSocket.SocketHandle,SD_SEND);
                return true;
            }

            //开始发包
            auto [pkg,len]=ConvertMessagesToNetStream(MyMessage);//将消息转换为网络字节流
            SendMessages(ConnectToServerSocket,pkg.data(),len);//调用发送消息函数
        }
        else {//ID非法
            //由recv获取ID非法的原因，此处直接重头开始循环获取输入
            continue;
        }
    }
    return true;
}

static bool RecvMessagesThread(SocketGuard& ConnectToServerSocket) {//接受消息,正常退出返回true,异常返回false
    while (true) {
        auto OptMessageJudging = RecvMessages(ConnectToServerSocket.SocketHandle,ReceiverTypes::Client);//阻塞接受消息,接收端(本端)类型是Client

        //异常消息
        if (OptMessageJudging==std::nullopt) {
            return false;
        }

        //接受服务器消息
        if (OptMessageJudging.value().SenderType==static_cast<uint32_t>(SenderTypes::Server)) {
            const Message& getMessage=OptMessageJudging.value();
            //探测包相关
            if (getMessage.MessageType==static_cast<uint32_t>(ServerMessageTypes::Probe)) {
                Message ProbePack;
                ProbePack.SenderType=static_cast<uint32_t>(SenderTypes::Client);
                ProbePack.MessageType=static_cast<uint32_t>(ClientMessageTypes::ReplyProbe);
                ProbePack.UserIDReceiver=0;

                auto [pkg,len]=ConvertMessagesToNetStream(ProbePack);//将消息转换为网络字节流
                SendMessages(ConnectToServerSocket,pkg.data(),len); //调用发送消息函数

                //std::lock_guard<std::mutex> IOlock(IOMutex);
                //std::cout<<"Reply the Probe"<<std::endl;
            }
            //登录相关
            if (getMessage.MessageType==static_cast<uint32_t>(ServerMessageTypes::LoginSuccessfulToken)) {//登录相关:登录成功
                std::unique_lock<std::mutex> Loginlock(LoginMutex);
                HaveLogged=true;
                HaveReplyLogged=true;
                Loginlock.unlock();
                LoginCV.notify_all();
                std::lock_guard<std::mutex> IOlock(IOMutex);
                std::cout<<"Login Successfully"<<std::endl;
            }
            else if (getMessage.MessageType==static_cast<uint32_t>(ServerMessageTypes::LoginFailedToken_UsedID)){//ID已被占用
                std::unique_lock<std::mutex> Loginlock(LoginMutex);
                HaveLogged=false;
                HaveReplyLogged=true;
                Loginlock.unlock();
                LoginCV.notify_all();
                std::lock_guard<std::mutex> IOlock(IOMutex);
                std::cout<<"This ID have been used"<<std::endl;
            }
            else if (getMessage.MessageType==static_cast<uint32_t>(ServerMessageTypes::LoginFailedToken_IDis0)) {//ID为0
                std::unique_lock<std::mutex> Loginlock(LoginMutex);
                HaveLogged=false;
                HaveReplyLogged=true;
                Loginlock.unlock();
                LoginCV.notify_all();
                std::lock_guard<std::mutex> IOlock(IOMutex);
                std::cout<<"ID can't be 0"<<std::endl;
            }
            //目标ID检验相关
            else if (getMessage.MessageType==static_cast<uint32_t>(ServerMessageTypes::LegalTargetID)) {
                std::unique_lock<std::mutex> IDJudgelock(IDJudgingMutex);
                HaveJudgedID=true;
                IDLegal=true;
                IDJudgingCV.notify_all();
                std::lock_guard<std::mutex> IOlock(IOMutex);
                std::cout<<"Legal Target."<<std::endl;
            }else if (getMessage.MessageType==static_cast<uint32_t>(ServerMessageTypes::IllegalTargetID_IDis0)) {
                std::unique_lock<std::mutex> IDJudgelock(IDJudgingMutex);
                HaveJudgedID=true;
                IDLegal=false;
                IDJudgingCV.notify_all();
                std::lock_guard<std::mutex> IOlock(IOMutex);
                std::cout<<"Target can't be 0"<<std::endl;
            }
            else if (getMessage.MessageType==static_cast<uint32_t>(ServerMessageTypes::IllegalTargetID_Invalid)) {
                std::unique_lock<std::mutex> IDJudgelock(IDJudgingMutex);
                HaveJudgedID=true;
                IDLegal=false;
                IDJudgingCV.notify_all();
                std::lock_guard<std::mutex> IOlock(IOMutex);
                std::cout<<"Target is Invalid"<<std::endl;
            }
            else if (getMessage.MessageType==static_cast<uint32_t>(ServerMessageTypes::IllegalTargetID_TargetSelf)) {
                std::unique_lock<std::mutex> IDJudgelock(IDJudgingMutex);
                HaveJudgedID=true;
                IDLegal=false;
                IDJudgingCV.notify_all();
                std::lock_guard<std::mutex> IOlock(IOMutex);
                std::cout<<"Target can't be self"<<std::endl;
            }
            //发送消息相关
            else if (getMessage.MessageType==static_cast<uint32_t>(ServerMessageTypes::ForwardSuccessfully)) {
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<std::endl<<"Send Successfully"<<std::endl;
            }
            else if (getMessage.MessageType==static_cast<uint32_t>(ServerMessageTypes::ForwardFailed)) {
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<std::endl<<"Send Failed"<<std::endl;
            }
            //普通转发消息
            else if (OptMessageJudging.value().MessageType==static_cast<uint32_t>(ServerMessageTypes::Forward)) {;
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<std::endl<<"Message Come from ID:"<<getMessage.UserIDSender<<" Contents:"<<getMessage.TextMessage;
            }
            //服务器断连相关
            else if (OptMessageJudging.value().MessageType==static_cast<uint32_t>(ServerMessageTypes::ServerSafeQuit)) {
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<std::endl<<"Server closed Connect Safely"<<std::endl;
                return true;
            }else if (OptMessageJudging.value().MessageType==static_cast<uint32_t>(ServerMessageTypes::ServerErrorQuit)) {
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<std::endl<<"Server closed Connect Wrongly"<<std::endl;
                return true;
            }
        }
    }
}

static void Quit(SocketGuard& ConnectToServerSocket) {
    shutdown(ConnectToServerSocket.SocketHandle,SD_SEND);
    ConnectToServerSocket.CloseSocketHandle();
    MyThreadsPool.StopThreadsPool();
}

int main() {
    WSAGuard wsaData{};
    int result = -1;
    if (!IsOK(JudgeType::WSAStartUp,wsaData.CreatedMessage)) {
        return 1;
    }

    SocketGuard ConnectToServerSocket{};
    ConnectToServerSocket.SocketHandle=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (!IsOK(JudgeType::SocketCreated,static_cast<int>(ConnectToServerSocket.SocketHandle))) {
        return 1;
    }

    ConnectToServerSocket.SocketHandleAddr.sin_family=AF_INET;
    inet_pton(AF_INET,IP,&ConnectToServerSocket.SocketHandleAddr.sin_addr);
    ConnectToServerSocket.SocketHandleAddr.sin_port=htons(PORT);

    result=connect(ConnectToServerSocket.SocketHandle,reinterpret_cast<sockaddr *>(&ConnectToServerSocket.SocketHandleAddr),sizeof(ConnectToServerSocket.SocketHandleAddr));
    if (!IsOK(JudgeType::SocketConnected,result)) {
        return 1;
    }

    std::unique_lock<std::mutex> IOlock(IOMutex);
    std::cout<<"connected successfully!"<<std::endl;
    IOlock.unlock();

    MyThreadsPool.AddTask(RecvMessagesThread,std::ref(ConnectToServerSocket));

    //登陆
    while (true) {
        IOlock.lock();
        std::cout<<"Input Your User ID: ";
        IOlock.unlock();
        CinRtStatus GetCinRtStatuts=InputCheck(MyMessage.UserIDSender);
        if (GetCinRtStatuts==CinRtStatus::Legal){
            auto LoginResult=MyThreadsPool.AddTask(WaitingLoginReply);
            LoginRequest(ConnectToServerSocket);
            if (LoginResult.get()) {
                //登陆成功,ID检验全部放服务端
                break;
            }
        }
        else if (GetCinRtStatuts==CinRtStatus::Illegal) {
            IOlock.lock();
            std::cout<<"Illegal Input!"<<std::endl;
            IOlock.unlock();
        }else {
            Quit(ConnectToServerSocket);
            return 1;
        }
    }

    auto SendThreadRtStatus=MyThreadsPool.AddTask(SendMessagesThread,std::ref(ConnectToServerSocket));
    if (SendThreadRtStatus.get()) {//正常关闭
        Quit(ConnectToServerSocket);
        return 0;
    }else {//异常退出
        Quit(ConnectToServerSocket);
        return 1;
    }
}
