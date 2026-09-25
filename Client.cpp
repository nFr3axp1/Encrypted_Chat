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


static void LoginRequest(const SocketGuard& ConnectToServerSocket) {
    MyMessage.MessageType=static_cast<uint32_t>(MessageType::Login);
    MyMessage.UserIDReceiver=0;

    auto [pkg,len]=ConvertMessagesToNetStream(MyMessage);//将消息转换为网络字节流
    SendMessages(ConnectToServerSocket.SocketHandle,pkg.data(),len); //调用发送消息函数
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

static bool SendMessagesThread(const SocketGuard& ConnectToServerSocket) {//正常关闭返回true
    while (true) {
        MyMessage.MessageType=static_cast<uint32_t>(MessageType::CheckID);
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
        SendMessages(ConnectToServerSocket.SocketHandle,pkg_only_id.data(),len_only_id);//调用发送消息函数

        auto IDJudgingResult=MyThreadsPool.AddTask(WaitingIDJudging);
        if (IDJudgingResult.get()) {//ID合法
            MyMessage.MessageType=static_cast<uint32_t>(MessageType::Normal);
            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<"Send Message:";
            IOlock.unlock();

            //输入Text字符串
            std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
            if (!std::getline(std::cin, MyMessage.TextMessage)) {// 处理输入流失效
                return false;
            }

            if (MyMessage.TextMessage=="quit") {
                MyMessage.MessageType=static_cast<uint32_t>(MessageType::ClientSafeQuit);
                auto [pkg,len]=ConvertMessagesToNetStream(MyMessage);//将消息转换为网络字节流
                SendMessages(ConnectToServerSocket.SocketHandle,pkg.data(),len);
                shutdown(ConnectToServerSocket.SocketHandle,SD_SEND);
                return true;
            }

            //开始发包
            auto [pkg,len]=ConvertMessagesToNetStream(MyMessage);//将消息转换为网络字节流
            SendMessages(ConnectToServerSocket.SocketHandle,pkg.data(),len);//调用发送消息函数
        }
        else {//ID非法
            //由recv获取ID非法的原因，此处直接重头开始循环获取输入
            continue;
        }
    }
    return true;
}

static bool RecvMessagesThread(const SocketGuard& ConnectToServerSocket) {//接受消息,正常退出返回true,异常返回false
    while (true) {
        auto OptMessageJudging = RecvMessages(ConnectToServerSocket.SocketHandle);

        if (OptMessageJudging==std::nullopt) {
            return false;
        }

        //接受服务器消息
        if (OptMessageJudging.value().MessageType==static_cast<uint32_t>(MessageType::Server)) {
            const Message& getMessage=OptMessageJudging.value();
            //登录相关
            if (getMessage.TextMessage==Message::LoginSuccessfulToken) {//登录相关:登录成功
                std::unique_lock<std::mutex> Loginlock(LoginMutex);
                HaveLogged=true;
                HaveReplyLogged=true;
                Loginlock.unlock();
                LoginCV.notify_all();
            }
            else if (getMessage.TextMessage==Message::LoginFailedToken_UsedID||getMessage.TextMessage==Message::LoginFailedToken_IDis0){//登录相关:ID已被占用或ID为0
                std::unique_lock<std::mutex> Loginlock(LoginMutex);
                HaveLogged=false;
                HaveReplyLogged=true;
                Loginlock.unlock();
                LoginCV.notify_all();
            }
            //目标ID检验相关
            else if (getMessage.TextMessage==Message::IDLegal) {
                std::unique_lock<std::mutex> IDJudgelock(IDJudgingMutex);
                HaveJudgedID=true;
                IDLegal=true;
                IDJudgingCV.notify_all();
            }else if (getMessage.TextMessage==Message::IDIllegal_IDis0||getMessage.TextMessage==Message::IDIllegal_Invalid||getMessage.TextMessage==Message::IDIllegal_TargetSelf) {
                std::unique_lock<std::mutex> IDJudgelock(IDJudgingMutex);
                HaveJudgedID=true;
                IDLegal=false;
                IDJudgingCV.notify_all();
            }
            //发送消息相关
            else if (getMessage.TextMessage==Message::SendSuccessfully) {
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<std::endl<<"Send Successfully"<<std::endl;
            }
            else if (getMessage.TextMessage==Message::SendFailed) {
                std::unique_lock<std::mutex> IOlock(IOMutex);
                std::cout<<std::endl<<"Send Failed"<<std::endl;
            }
            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<std::endl<<"Message from Server:"<<getMessage.TextMessage<<std::endl;
        }
        //普通转发消息
        if (OptMessageJudging.value().MessageType==static_cast<uint32_t>(MessageType::Normal)) {
            const Message& getMessage=OptMessageJudging.value();
            std::unique_lock<std::mutex> IOlock(IOMutex);
            std::cout<<std::endl<<"Message Come from ID:"<<getMessage.UserIDSender<<" Contents:"<<getMessage.TextMessage;
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
