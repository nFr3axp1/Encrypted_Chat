#pragma once
#include<mutex>
#include<iostream>
#include<functional>

enum class CinRtStatus {
    Legal,EOF_,Illegal
};

template<typename InputType>
CinRtStatus InputCheck(InputType &&Input) {
    if (std::cin>>Input) {
        return CinRtStatus::Legal;
    }
    else if (!std::cin.eof()) {//不为eof输入符但非法时
        std::cin.clear();
        std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
        return CinRtStatus::Illegal;
    }else {//为eof输入符时结束程序
        return CinRtStatus::EOF_;
    }
}
