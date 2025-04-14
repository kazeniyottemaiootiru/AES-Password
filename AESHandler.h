#ifndef _AESHANDLER_H_
#define _AESHANDLER_H_

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "AESKeySchedule.h"

using namespace std;

const size_t BLOCK_SIZE = 16;
const size_t BUFFER_SIZE = 64 * 1024;

class AESHandler {
private:
    string key = string(16, '\0');  // �û������ԭʼ��Կ�����ȹ̶�Ϊ16�ֽ�
    string roundKey = string(176, '\0');    // ��չ�������Կ����176�ֽڣ�11 �֣�

    // ���ݳ�ʼ��Կ����11������Կ����176�ֽڣ�
    void KeyExpansion() {
        string temp(4, '\0');
        memcpy(&roundKey[0], &key[0], 16);
        for (int i = 16, j = 1; i < 176; i += 4) {
            memcpy(&temp[0], &roundKey[i - 4], 4);
            if (i % 16 == 0) {
                char k = temp[0];
                temp[0] = AESKeySchedule::sbox[(unsigned char)temp[1]] ^ AESKeySchedule::Rcon[(j - 1) * 4];
                temp[1] = AESKeySchedule::sbox[(unsigned char)temp[2]];
                temp[2] = AESKeySchedule::sbox[(unsigned char)temp[3]];
                temp[3] = AESKeySchedule::sbox[(unsigned char)k];
                j++;
            }
            for (int j = 0; j < 4; j++)
                roundKey[i + j] = roundKey[i + j - 16] ^ temp[j];
        }
    }

    // ʹ��S-box��state�е�ÿ���ֽڽ����滻
    void SubBytes(vector<unsigned char>& state) {
        for (auto& c : state) {
            c = AESKeySchedule::sbox[c];
        }
    }

    // ʹ����S-box��state�е�ÿ���ֽڽ������滻
    void InverseSubBytes(vector<unsigned char>& state) {
        for (auto& c : state) {
            c = AESKeySchedule::rsbox[c];
        }
    }

    // ��state�뵱ǰ����Կ�������
    void AddRoundKey(vector<unsigned char>& state, int round) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] ^= roundKey[round * BLOCK_SIZE + i];
        }
    }

    // ʵ������λ����
    void ShiftRows(vector<unsigned char>& state) {
        vector<unsigned char> temp = state;
        temp[1] = state[5];  temp[5] = state[9];  temp[9] = state[13]; temp[13] = state[1];
        temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2];  temp[14] = state[6];
        temp[3] = state[15]; temp[7] = state[3];  temp[11] = state[7];  temp[15] = state[11];
        state = temp;
    }

    // ʵ����������λ����
    void InverseShiftRows(vector<unsigned char>& state) {
        vector<unsigned char> temp = state;
        temp[1] = state[13]; temp[5] = state[1];  temp[9] = state[5];  temp[13] = state[9];
        temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2];  temp[14] = state[6];
        temp[3] = state[7];  temp[7] = state[11]; temp[11] = state[15]; temp[15] = state[3];
        state = temp;
    }

    // ʵ���л�������
    void MixColumns(vector<unsigned char>& state) {
        for (int c = 0; c < 4; ++c) {
            unsigned char a0 = state[4 * c];
            unsigned char a1 = state[4 * c + 1];
            unsigned char a2 = state[4 * c + 2];
            unsigned char a3 = state[4 * c + 3];

            state[4 * c] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
            state[4 * c + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
            state[4 * c + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
            state[4 * c + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
        }
    }

    // ʵ�������л�������
    void InverseMixColumns(vector<unsigned char>& state) {
        for (int c = 0; c < 4; ++c) {
            unsigned char a0 = state[4 * c];
            unsigned char a1 = state[4 * c + 1];
            unsigned char a2 = state[4 * c + 2];
            unsigned char a3 = state[4 * c + 3];

            state[4 * c] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
            state[4 * c + 1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
            state[4 * c + 2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
            state[4 * c + 3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
        }
    }

    // ������GF(2^8)�еĳ˷�ʵ��
    unsigned char gmul(unsigned char a, unsigned char b) {
        unsigned char p = 0;
        while (b) {
            if (b & 1) p ^= a;
            bool hi_bit_set = a & 0x80;
            a <<= 1;
            if (hi_bit_set) a ^= 0x1B;
            b >>= 1;
        }
        return p;
    }

    // �Բ���16�ֽڵ����ݿ����PKCS#7���
    void padBlock(vector<unsigned char>& block) {
        size_t padLen = BLOCK_SIZE - block.size();
        // PKCS#7 ��䣺ÿ������ֽڵ�ֵ������䳤��
        block.resize(BLOCK_SIZE, static_cast<unsigned char>(padLen));
    }

    // �Ƴ����ݿ�ĩβ��PKCS#7���
    void unpadBlock(vector<unsigned char>& block) {
        unsigned char padLen = block.back();
        // �����䳤���Ƿ���Ч
        if (padLen > 0 && padLen <= BLOCK_SIZE) {
            block.resize(block.size() - padLen);
        }
    }

    // ��16�ֽ����ݿ����AES-128����
    void AES_encrypt(vector<unsigned char>& block) {
        AddRoundKey(block, 0);
        for (int round = 1; round < 10; round++) {
            SubBytes(block);
            ShiftRows(block);
            MixColumns(block);
            AddRoundKey(block, round);
        }
        SubBytes(block);
        ShiftRows(block);
        AddRoundKey(block, 10);
    }

    // ��16�ֽ����ݿ����AES-128����
    void AES_decrypt(vector<unsigned char>& block) {
        AddRoundKey(block, 10);
        for (int round = 9; round > 0; round--) {
            InverseShiftRows(block);
            InverseSubBytes(block);
            AddRoundKey(block, round);
            InverseMixColumns(block);
        }
        InverseShiftRows(block);
        InverseSubBytes(block);
        AddRoundKey(block, 0);
        //InverseMixColumns(block);
    }

public:
    /*
    * ���췽��������һ��16�ֽ���Կ���г�ʼ��
    * �׳��쳣�������Կ���Ȳ��� 16 �ֽ�
    */ 
    AESHandler(const string& userKey) {
        if (userKey.size() != BLOCK_SIZE) throw runtime_error("��Կ����ӦΪ16�ֽڣ�");
        key = userKey;
        AESKeySchedule::generateSBox();
        AESKeySchedule::generateRcon();
        KeyExpansion();
    }

    /*
    * ��ָ�������ļ�����AES���ܣ��������д������ļ�
    * ������
    * inputPath��ԭʼ�ļ�·��
    * outputPath����������ļ�·��
    * ����ֵ��
    * true�����ܳɹ���
    * false���ļ���ʧ�ܻ��д����
    */ 
    bool encryptFile(const string& inputPath, const string& outputPath) {
        ifstream inFile(inputPath, ios::binary);
        ofstream outFile(outputPath, ios::binary);
        if (!inFile || !outFile) {
            cerr << "�޷����ļ���" << endl;
            return false;
        }

        while (!inFile.eof()) {
            vector<unsigned char> buffer(BLOCK_SIZE);
            inFile.read(reinterpret_cast<char*>(buffer.data()), BLOCK_SIZE);
            size_t bytesRead = inFile.gcount();

            if (bytesRead == 0) break;

            buffer.resize(bytesRead);
            if (bytesRead < BLOCK_SIZE || inFile.peek() == EOF) {
                padBlock(buffer);
            }

            AES_encrypt(buffer);
            outFile.write(reinterpret_cast<const char*>(buffer.data()), BLOCK_SIZE);
        }
        return true;
    }

    /*
    * ��ָ�������ļ�����AES���ܣ��������д������ļ�
    * ������
    * inputPath�������ļ�·��
    * outputPath����������ļ�·��
    * ����ֵ��
    * true�����ܳɹ���
    * false���ļ���ʧ�ܻ��д����
    */
    bool decryptFile(const string& inputPath, const string& outputPath) {
        ifstream inFile(inputPath, ios::binary);
        ofstream outFile(outputPath, ios::binary);
        if (!inFile || !outFile) {
            cerr << "�޷����ļ���" << endl;
            return false;
        }

        vector<unsigned char> buffer(BLOCK_SIZE);
        streampos fileSize = inFile.seekg(0, ios::end).tellg();
        inFile.seekg(0, ios::beg);

        while (inFile.tellg() < fileSize) {
            inFile.read(reinterpret_cast<char*>(buffer.data()), BLOCK_SIZE);
            size_t bytesRead = inFile.gcount();
            if (bytesRead < BLOCK_SIZE) break;

            AES_decrypt(buffer);

            if (inFile.tellg() == fileSize) {
                unpadBlock(buffer);
            }

            outFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        }
        return true;
    }
};

#endif // !_AESHANDLER_H_
