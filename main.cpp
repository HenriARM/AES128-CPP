#include <iostream>
#include <sstream>

#define NR 10  // Number of rounds
#define NB 4   // Number of words in State
#define NK 4   // Number of words in Key

#define PLAINTEXT_SIZE 1024
#define WORD_SIZE 4
#define KEY_SIZE NK * WORD_SIZE
#define STATE_SIZE NB * WORD_SIZE

#define MODULE 0x011b // used in polynomial multiplication 283 == 100011011 == x^8 + x^4 + x^3 + x + 1

using namespace std;

// Rijndael S-box
unsigned char s[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Inverse Rijndael S-box
unsigned char inv_s[256] = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

unsigned char rcon[256] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

void printHex(string msg, unsigned char *a) {
    cout << msg;
    for (int i = 0; i < 16; i++) cout << hex << (int) a[i] << " ";
    cout << endl;
}

// TODO: divide into 3 functions
void SubRotRcon(unsigned char *in, unsigned char i) {
    // Rotate left by one byte
    unsigned char t = in[0];
    in[0] = in[1];
    in[1] = in[2];
    in[2] = in[3];
    in[3] = t;
    // S-box 4 bytes
    in[0] = s[in[0]];
    in[1] = s[in[1]];
    in[2] = s[in[2]];
    in[3] = s[in[3]];
    // RCon
    in[0] ^= rcon[i];
}

void KeyExpansion(unsigned char inputKey[KEY_SIZE], unsigned char expandedKey[NR * KEY_SIZE]) {
    for (int i = 0; i < 16; i++) expandedKey[i] = inputKey[i];
    int bytesGenerated = 16;
    int rconIteration = 1;
    unsigned char tmpCore[4];
    while (bytesGenerated < NR * (KEY_SIZE + 2)) {
        for (int i = 0; i < 4; i++) tmpCore[i] = expandedKey[i + bytesGenerated - 4];
        if (bytesGenerated % 16 == 0) SubRotRcon(tmpCore, rconIteration++);
        for (unsigned char a = 0; a < 4; a++) {
            expandedKey[bytesGenerated] = expandedKey[bytesGenerated - 16] ^ tmpCore[a];
            bytesGenerated++;
        }
    }
}

uint8_t mult(uint8_t n, uint8_t m) {
    // polynomial multiplication
    uint16_t mul = (uint16_t) n;
    uint16_t res = 0;
    for (; m > 0; m >>= 1) {
        if (m & 0x1) res ^= mul;
        mul <<= 1;
    }
    // polynomial division, returning the remainder
    uint16_t shifted_modulus = MODULE << 7;
    uint16_t test_bit = 0x8000;
    while (res >= 0x0100) {
        if (test_bit & res) res ^= shifted_modulus;
        test_bit >>= 1;
        shifted_modulus >>= 1;
    }
    return (uint8_t) res;
}

// ============================================ ENCRYPTION FUNCTIONS =============================================== //

void AddRoundKey(unsigned char *state, unsigned char *roundKey) {
    for (int i = 0; i < KEY_SIZE; i++) state[i] ^= roundKey[i];
}

void SubBytes(unsigned char *state) {
    for (int i = 0; i < KEY_SIZE; i++) state[i] = s[state[i]];
}

void ShiftRows(unsigned char *state) {
    unsigned char tmp[STATE_SIZE];
    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];
    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];
    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];
    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];
    for (int i = 0; i < 16; i++) state[i] = tmp[i];
}

void MixColumns(unsigned char *state) {
    unsigned char tmp[16];
    tmp[0] = (unsigned char) mult(2, state[0]) ^ mult(3, state[1]) ^ state[2] ^ state[3];
    tmp[1] = (unsigned char) state[0] ^ mult(2, state[1]) ^ mult(3, state[2]) ^ state[3];
    tmp[2] = (unsigned char) state[0] ^ state[1] ^ mult(2, state[2]) ^ mult(3, state[3]);
    tmp[3] = (unsigned char) mult(3, state[0]) ^ state[1] ^ state[2] ^ mult(2, state[3]);
    tmp[4] = (unsigned char) mult(2, state[4]) ^ mult(3, state[5]) ^ state[6] ^ state[7];
    tmp[5] = (unsigned char) state[4] ^ mult(2, state[5]) ^ mult(3, state[6]) ^ state[7];
    tmp[6] = (unsigned char) state[4] ^ state[5] ^ mult(2, state[6]) ^ mult(3, state[7]);
    tmp[7] = (unsigned char) mult(3, state[4]) ^ state[5] ^ state[6] ^ mult(2, state[7]);
    tmp[8] = (unsigned char) mult(2, state[8]) ^ mult(3, state[9]) ^ state[10] ^ state[11];
    tmp[9] = (unsigned char) state[8] ^ mult(2, state[9]) ^ mult(3, state[10]) ^ state[11];
    tmp[10] = (unsigned char) state[8] ^ state[9] ^ mult(2, state[10]) ^ mult(3, state[11]);
    tmp[11] = (unsigned char) mult(3, state[8]) ^ state[9] ^ state[10] ^ mult(2, state[11]);
    tmp[12] = (unsigned char) mult(2, state[12]) ^ mult(3, state[13]) ^ state[14] ^ state[15];
    tmp[13] = (unsigned char) state[12] ^ mult(2, state[13]) ^ mult(3, state[14]) ^ state[15];
    tmp[14] = (unsigned char) state[12] ^ state[13] ^ mult(2, state[14]) ^ mult(3, state[15]);
    tmp[15] = (unsigned char) mult(3, state[12]) ^ state[13] ^ state[14] ^ mult(2, state[15]);
    for (int i = 0; i < 16; i++) state[i] = tmp[i];
}

void encrypt(const unsigned char *plaintext, unsigned char *expandedKey, unsigned char *ciphertext) {
    unsigned char state[STATE_SIZE];
    fill(state, state + STATE_SIZE, 0);
    // copy plaintext at first into state
    for (int i = 0; i < KEY_SIZE; i++) state[i] = plaintext[i];
    // add initial round key
    AddRoundKey(state, expandedKey);
    // encrypt main rounds
    for (int i = 1; i < NR; i++) {
        cout << endl << "Round " << i << ": " << endl;
        printHex("Start: ", state);
        SubBytes(state);
        printHex("After SubBytes: ", state);
        ShiftRows(state);
        printHex("After ShiftRows: ", state);
        MixColumns(state);
        printHex("After MixColumns: ", state);
        unsigned char *key = expandedKey + (KEY_SIZE * (i));
        printHex("Round Key Value: ", key);
        AddRoundKey(state, key);
    }
    cout << endl << "Round " << NR << ": " << endl;
    printHex("Start: ", state);
    SubBytes(state);
    printHex("After SubBytes: ", state);
    ShiftRows(state);
    printHex("After ShiftRows: ", state);
    unsigned char *key = expandedKey + (KEY_SIZE * (NR));
    printHex("Round Key Value: ", key);
    AddRoundKey(state, key);
    cout << endl;
    printHex("Cipher text: ", state);
    for (int i = 0; i < STATE_SIZE; i++) ciphertext[i] = state[i];

//    printHex("Round Key Value: ", expandedKey + (KEY_SIZE * (NR)));
}
// ============================================ DECRYPTION FUNCTIONS =============================================== //

//mul9, mul11, mul13, mul14
void InvMixColumns(unsigned char *state) {
    unsigned char tmp[STATE_SIZE];
    tmp[0] = (unsigned char) mult(2, state[0]) ^ mult(3, state[1]) ^ state[2] ^ state[3];

    tmp[0] = (unsigned char) mult(14, state[0]) ^ mult(11, state[1]) ^ mult(13, state[2]) ^ mult(9, state[3]);
    tmp[1] = (unsigned char) mult(9, state[0]) ^ mult(14, state[1]) ^ mult(11, state[2]) ^ mult(13, state[3]);
    tmp[2] = (unsigned char) mult(13, state[0]) ^ mult(9, state[1]) ^ mult(14, state[2]) ^ mult(11, state[3]);
    tmp[3] = (unsigned char) mult(11, state[0]) ^ mult(13, state[1]) ^ mult(9, state[2]) ^ mult(14, state[3]);

    tmp[4] = (unsigned char) mult(14, state[4]) ^ mult(11, state[5]) ^ mult(13, state[6]) ^ mult(9, state[7]);
    tmp[5] = (unsigned char) mult(9, state[4]) ^ mult(14, state[5]) ^ mult(11, state[6]) ^ mult(13, state[7]);
    tmp[6] = (unsigned char) mult(13, state[4]) ^ mult(9, state[5]) ^ mult(14, state[6]) ^ mult(11, state[7]);
    tmp[7] = (unsigned char) mult(11, state[4]) ^ mult(13, state[5]) ^ mult(9, state[6]) ^ mult(14, state[7]);

    tmp[8] = (unsigned char) mult(14, state[8]) ^ mult(11, state[9]) ^ mult(13, state[10]) ^ mult(9, state[11]);
    tmp[9] = (unsigned char) mult(9, state[8]) ^ mult(14, state[9]) ^ mult(11, state[10]) ^ mult(13, state[11]);
    tmp[10] = (unsigned char) mult(13, state[8]) ^ mult(9, state[9]) ^ mult(14, state[10]) ^ mult(11, state[11]);
    tmp[11] = (unsigned char) mult(11, state[8]) ^ mult(13, state[9]) ^ mult(9, state[10]) ^ mult(14, state[11]);

    tmp[12] = (unsigned char) mult(14, state[12]) ^ mult(11, state[13]) ^ mult(13, state[14]) ^ mult(9, state[15]);
    tmp[13] = (unsigned char) mult(9, state[12]) ^ mult(14, state[13]) ^ mult(11, state[14]) ^ mult(13, state[15]);
    tmp[14] = (unsigned char) mult(13, state[12]) ^ mult(9, state[13]) ^ mult(14, state[14]) ^ mult(11, state[15]);
    tmp[15] = (unsigned char) mult(11, state[12]) ^ mult(13, state[13]) ^ mult(9, state[14]) ^ mult(14, state[15]);
    for (int i = 0; i < 16; i++) state[i] = tmp[i];
}

void InvShiftRows(unsigned char *state) {
    unsigned char tmp[STATE_SIZE];
    tmp[0] = state[0];
    tmp[1] = state[13];
    tmp[2] = state[10];
    tmp[3] = state[7];
    tmp[4] = state[4];
    tmp[5] = state[1];
    tmp[6] = state[14];
    tmp[7] = state[11];
    tmp[8] = state[8];
    tmp[9] = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];
    tmp[12] = state[12];
    tmp[13] = state[9];
    tmp[14] = state[6];
    tmp[15] = state[3];
    for (int i = 0; i < 16; i++) state[i] = tmp[i];
}

void InvSubBytes(unsigned char *state) {
    for (int i = 0; i < KEY_SIZE; i++) state[i] = inv_s[state[i]];
}

void decrypt(unsigned char *ciphertextBlock, unsigned char *expandedKey, unsigned char *deciphertextBlock) {
    unsigned char state[STATE_SIZE];
    fill(state, state + STATE_SIZE, 0);
    // copy plaintext at first into state
    for (int i = 0; i < KEY_SIZE; i++) state[i] = ciphertextBlock[i];

    unsigned char *key = expandedKey + (KEY_SIZE * (NR));
    printHex("Last Key: ", key);
    AddRoundKey(state, key);
    cout << endl << "Round " << 10 << ": " << endl;
    printHex("Start: ", state);
    InvShiftRows(state);
    printHex("After InvShiftRows: ", state);
    InvSubBytes(state);
    printHex("After InvSubBytes: ", state);
    for (int i = 9; i >= 1; i--) {
        key = expandedKey + (16 * i);
        printHex("Round Key Value: ", key);
        AddRoundKey(state, key);
        printHex("Add Round Key Value: ", state);
        InvMixColumns(state);
        cout << endl << "Round " << i << ": " << endl;
        printHex("Start: ", state);
        InvShiftRows(state);
        printHex("After InvShiftRows: ", state);
        InvSubBytes(state);
        printHex("After InvSubBytes: ", state);
    }
    key = expandedKey + 0;
    printHex("Round Key Value: ", key);
    AddRoundKey(state, key);
    printHex("Add Round Key Value: ", state);
    cout << endl;
    printHex("Plaintext: ", state);
}
// ========================================================================================================== //

int main() {
    // ======================== INSERT PLAINTEXT =================================== //
    unsigned char plaintext[PLAINTEXT_SIZE + 100];
    fill(plaintext, plaintext + PLAINTEXT_SIZE, 0);
//    string plaintextHex = "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff";
        string plaintextHex = "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34";
    istringstream plaintextStream(plaintextHex);
    unsigned int c = 0;
    int i = 0;
    while (plaintextStream >> hex >> c) {
        plaintext[i] = c;
        i++;
    }

    // ======================== INSERT KEY =================================== //
    unsigned char key[KEY_SIZE + 100];
    fill(key, key + KEY_SIZE, 0);
//    string keyHex = "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f";
        string keyHex = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";
    istringstream keyStream(keyHex);
    c = 0;
    i = 0;
    while (keyStream >> hex >> c) {
        key[i] = c;
        i++;
    }

    // find last block index
    for (i = PLAINTEXT_SIZE - 1; i > 0; i--) if (plaintext[i]) break;
    int plaintextEnd = i + 1;

    // print Plaintext and Cypher key
    cout << "Plaintext: ";
    for (i = 0; i < PLAINTEXT_SIZE; ++i) if (plaintext[i] != 0) cout << hex << (int) plaintext[i] << " ";
    cout << endl;
    cout << "Key: ";
    for (i = 0; i < KEY_SIZE; ++i) cout << hex << (int) key[i] << " ";
    cout << endl;

    // ======================== ENCRYPTION =================================== //

    unsigned char expandedKey[NR * KEY_SIZE + 100];
    fill(expandedKey, expandedKey + NR * KEY_SIZE, 0);
    //   generate round keys
    KeyExpansion(key, expandedKey);
    unsigned char ciphertext[PLAINTEXT_SIZE + 100];
    fill(ciphertext, ciphertext + PLAINTEXT_SIZE, 0);
    //   encrypt each block
    unsigned char *plaintextBlock = plaintext;
    unsigned char *ciphertextBlock = ciphertext;
    i = 0;
    do {
        encrypt(plaintextBlock, expandedKey, ciphertextBlock);
        i++;
        plaintextBlock += i * KEY_SIZE;
        ciphertextBlock += i * KEY_SIZE;
    } while (plaintextBlock - plaintext < plaintextEnd);

    // ======================== DECRYPTION =================================== //

    // find ciphertext last block index
    for (i = PLAINTEXT_SIZE - 1; i > 0; i--) if (ciphertext[i]) break;
    int ciphertextEnd = i + 1;

    unsigned char deciphertext[PLAINTEXT_SIZE + 100];
    fill(deciphertext, deciphertext + PLAINTEXT_SIZE, 0);

    // round keys already generated

    // decrypt each block
    ciphertextBlock = ciphertext;
    unsigned char *deciphertextBlock = deciphertext;
    i = 0;
    do {
        decrypt(ciphertextBlock, expandedKey, deciphertextBlock);
        i++;
        ciphertextBlock += i * KEY_SIZE;
        deciphertextBlock += i * KEY_SIZE;
    } while (ciphertextBlock - ciphertext < ciphertextEnd);
}