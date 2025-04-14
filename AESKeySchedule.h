#ifndef _AESKEYSCHEDULE_H_
#define _AESKEYSCHEDULE_H_

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

using namespace std;

class AESKeySchedule {
public:
    static vector<unsigned char> sbox;  // 存储AES算法中的SubBytes变换所用的S-box表（替代字节查表）
    static vector<unsigned char> rsbox; // 存储逆S-box，用于逆变换InverseSubBytes
    static vector<unsigned char> Rcon;  // 存储轮常量，用于密钥扩展过程中的特定步骤

    // 在GF(2^8)有限域中对两个字节进行乘法，用于AES MixColumns和Rcon生成
    static unsigned char gmul(unsigned char a, unsigned char b) {
        unsigned char p = 0;
        for (int i = 0; i < 8; i++) {
            if (b & 1) p ^= a;
            bool hiBitSet = a & 0x80;
            a <<= 1;
            if (hiBitSet) a ^= 0x1B;
            b >>= 1;
        }
        return p;
    }

    // 计算AES算法中所需的GF(2^8)上元素的乘法逆0的逆定义为0，其他值返回其逆元
    static unsigned char gf_inv(unsigned char a) {
        if (a == 0) return 0;
        for (int i = 1; i < 256; i++) {
            if (gmul(a, i) == 1) return i;
        }
        return 0;
    }

    // 对输入字节进行比特级仿射变换，是构建AES S-box的一部分（在求逆之后使用）
    static unsigned char affine(unsigned char x) {
        unsigned char result = 0;
        for (int i = 0; i < 8; i++) {
            result |= (((x >> i) & 1)
                ^ ((x >> ((i + 4) % 8)) & 1)
                ^ ((x >> ((i + 5) % 8)) & 1)
                ^ ((x >> ((i + 6) % 8)) & 1)
                ^ ((x >> ((i + 7) % 8)) & 1)
                ^ 1) << i;
        }
        return result;
    }

    // 遍历所有0~255字节，先进行有限域求逆，再进行仿射变换，生成AES S-box与rsbox
    static void generateSBox() {
        sbox.resize(256);
        rsbox.resize(256);
        for (int i = 0; i < 256; i++) {
            unsigned char inv = gf_inv(i);
            unsigned char val = affine(inv);
            sbox[i] = val;
            rsbox[val] = i;
        }
    }

    // 生成AES所需的10轮轮常量（每轮一个4字节block），用于密钥扩展中的KeyExpansion步骤
    static void generateRcon() {
        Rcon.resize(10 * 4);
        unsigned char r = 1;
        for (int i = 0; i < 10; i++) {
            Rcon[i * 4] = r;
            Rcon[i * 4 + 1] = 0;
            Rcon[i * 4 + 2] = 0;
            Rcon[i * 4 + 3] = 0;
            r = gmul(r, 2);
        }
    }
};

#endif