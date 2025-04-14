#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "AESKeySchedule.h"
#include "AESHandler.h"

using namespace std;

vector<unsigned char> AESKeySchedule::sbox;
vector<unsigned char> AESKeySchedule::rsbox;
vector<unsigned char> AESKeySchedule::Rcon;

bool handleKey(string& key) {
    if (key.size() > BLOCK_SIZE) {
        cerr << "错误：密钥长度应为16字节。" << endl;
        return true;
    }
    else if (key.size() < BLOCK_SIZE) {
        // 将密钥补全到16字节，使用ASCI 码中二进制为00000000(即'\0')补全
        key.append(BLOCK_SIZE - key.size(), '\0');
        return false;
    }
}

int main() {
    string choice, inputPath, outputPath, userKey;
    bool flag = true;

    cout << "#######################" << endl << "#    AES密码操作器    #" << endl <<
        "#######################" << endl;
    while (flag){
        cout << "请输入16字节的密钥（可为空）：";
        getline(cin, userKey);

        flag = handleKey(userKey);  // 调用函数处理密钥
    }
    
    AESHandler aes(userKey);

    cout << "1. 加密文件" << endl << "2. 解密文件" << endl << "请选择：";
    cin >> choice;
    cin.ignore();

    if (choice == "1") {
        cout << "请输入要加密的文件路径: ";
        getline(cin, inputPath);
        cout << "请输入加密后文件的保存路径: ";
        getline(cin, outputPath);
        aes.encryptFile(inputPath, outputPath);  // 执行文件加密
    }
    else if (choice == "2") {
        cout << "请输入要解密的文件路径: ";
        getline(cin, inputPath);
        cout << "请输入解密后文件的保存路径: ";
        getline(cin, outputPath);
        aes.decryptFile(inputPath, outputPath);  // 执行文件解密
    }
    else {
        cerr << "无效选项！" << endl;
    }
    return 0;
}