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
    string key = string(16, '\0');  // 用户输入的原始密钥，长度固定为16字节
    string roundKey = string(176, '\0');    // 扩展后的轮密钥，共176字节（11 轮）

    // 根据初始密钥生成11个轮密钥（共176字节）
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

    // 使用S-box对state中的每个字节进行替换
    void SubBytes(vector<unsigned char>& state) {
        for (auto& c : state) {
            c = AESKeySchedule::sbox[c];
        }
    }

    // 使用逆S-box对state中的每个字节进行逆替换
    void InverseSubBytes(vector<unsigned char>& state) {
        for (auto& c : state) {
            c = AESKeySchedule::rsbox[c];
        }
    }

    // 将state与当前轮密钥进行异或
    void AddRoundKey(vector<unsigned char>& state, int round) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] ^= roundKey[round * BLOCK_SIZE + i];
        }
    }

    // 实现行移位操作
    void ShiftRows(vector<unsigned char>& state) {
        vector<unsigned char> temp = state;
        temp[1] = state[5];  temp[5] = state[9];  temp[9] = state[13]; temp[13] = state[1];
        temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2];  temp[14] = state[6];
        temp[3] = state[15]; temp[7] = state[3];  temp[11] = state[7];  temp[15] = state[11];
        state = temp;
    }

    // 实现逆向行移位操作
    void InverseShiftRows(vector<unsigned char>& state) {
        vector<unsigned char> temp = state;
        temp[1] = state[13]; temp[5] = state[1];  temp[9] = state[5];  temp[13] = state[9];
        temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2];  temp[14] = state[6];
        temp[3] = state[7];  temp[7] = state[11]; temp[11] = state[15]; temp[15] = state[3];
        state = temp;
    }

    // 实现列混淆操作
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

    // 实现逆向列混淆操作
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

    // 有限域GF(2^8)中的乘法实现
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

    // 对不满16字节的数据块进行PKCS#7填充
    void padBlock(vector<unsigned char>& block) {
        size_t padLen = BLOCK_SIZE - block.size();
        // PKCS#7 填充：每个填充字节的值等于填充长度
        block.resize(BLOCK_SIZE, static_cast<unsigned char>(padLen));
    }

    // 移除数据块末尾的PKCS#7填充
    void unpadBlock(vector<unsigned char>& block) {
        unsigned char padLen = block.back();
        // 检查填充长度是否有效
        if (padLen > 0 && padLen <= BLOCK_SIZE) {
            block.resize(block.size() - padLen);
        }
    }

    // 对16字节数据块进行AES-128加密
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

    // 对16字节数据块进行AES-128解密
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
    * 构造方法，接收一个16字节密钥进行初始化
    * 抛出异常：如果密钥长度不是 16 字节
    */ 
    AESHandler(const string& userKey) {
        if (userKey.size() != BLOCK_SIZE) throw runtime_error("密钥长度应为16字节！");
        key = userKey;
        AESKeySchedule::generateSBox();
        AESKeySchedule::generateRcon();
        KeyExpansion();
    }

    /*
    * 对指定输入文件进行AES加密，并将结果写入输出文件
    * 参数：
    * inputPath：原始文件路径
    * outputPath：输出加密文件路径
    * 返回值：
    * true：加密成功；
    * false：文件打开失败或读写错误
    */ 
    bool encryptFile(const string& inputPath, const string& outputPath) {
        ifstream inFile(inputPath, ios::binary);
        ofstream outFile(outputPath, ios::binary);
        if (!inFile || !outFile) {
            cerr << "无法打开文件！" << endl;
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
    * 对指定输入文件进行AES解密，并将结果写入输出文件
    * 参数：
    * inputPath：加密文件路径
    * outputPath：输出解密文件路径
    * 返回值：
    * true：解密成功；
    * false：文件打开失败或读写错误
    */
    bool decryptFile(const string& inputPath, const string& outputPath) {
        ifstream inFile(inputPath, ios::binary);
        ofstream outFile(outputPath, ios::binary);
        if (!inFile || !outFile) {
            cerr << "无法打开文件！" << endl;
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
