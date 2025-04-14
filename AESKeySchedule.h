#ifndef _AESKEYSCHEDULE_H_
#define _AESKEYSCHEDULE_H_

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

using namespace std;

class AESKeySchedule {
public:
    static vector<unsigned char> sbox;  // �洢AES�㷨�е�SubBytes�任���õ�S-box������ֽڲ��
    static vector<unsigned char> rsbox; // �洢��S-box��������任InverseSubBytes
    static vector<unsigned char> Rcon;  // �洢�ֳ�����������Կ��չ�����е��ض�����

    // ��GF(2^8)�������ж������ֽڽ��г˷�������AES MixColumns��Rcon����
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

    // ����AES�㷨�������GF(2^8)��Ԫ�صĳ˷���0���涨��Ϊ0������ֵ��������Ԫ
    static unsigned char gf_inv(unsigned char a) {
        if (a == 0) return 0;
        for (int i = 1; i < 256; i++) {
            if (gmul(a, i) == 1) return i;
        }
        return 0;
    }

    // �������ֽڽ��б��ؼ�����任���ǹ���AES S-box��һ���֣�������֮��ʹ�ã�
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

    // ��������0~255�ֽڣ��Ƚ������������棬�ٽ��з���任������AES S-box��rsbox
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

    // ����AES�����10���ֳ�����ÿ��һ��4�ֽ�block����������Կ��չ�е�KeyExpansion����
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