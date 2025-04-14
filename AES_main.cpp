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
        cerr << "������Կ����ӦΪ16�ֽڡ�" << endl;
        return true;
    }
    else if (key.size() < BLOCK_SIZE) {
        // ����Կ��ȫ��16�ֽڣ�ʹ��ASCI ���ж�����Ϊ00000000(��'\0')��ȫ
        key.append(BLOCK_SIZE - key.size(), '\0');
        return false;
    }
}

int main() {
    string choice, inputPath, outputPath, userKey;
    bool flag = true;

    cout << "#######################" << endl << "#    AES���������    #" << endl <<
        "#######################" << endl;
    while (flag){
        cout << "������16�ֽڵ���Կ����Ϊ�գ���";
        getline(cin, userKey);

        flag = handleKey(userKey);  // ���ú���������Կ
    }
    
    AESHandler aes(userKey);

    cout << "1. �����ļ�" << endl << "2. �����ļ�" << endl << "��ѡ��";
    cin >> choice;
    cin.ignore();

    if (choice == "1") {
        cout << "������Ҫ���ܵ��ļ�·��: ";
        getline(cin, inputPath);
        cout << "��������ܺ��ļ��ı���·��: ";
        getline(cin, outputPath);
        aes.encryptFile(inputPath, outputPath);  // ִ���ļ�����
    }
    else if (choice == "2") {
        cout << "������Ҫ���ܵ��ļ�·��: ";
        getline(cin, inputPath);
        cout << "��������ܺ��ļ��ı���·��: ";
        getline(cin, outputPath);
        aes.decryptFile(inputPath, outputPath);  // ִ���ļ�����
    }
    else {
        cerr << "��Чѡ�" << endl;
    }
    return 0;
}