#include <iostream>
#include <string>
#include <cstdint>
#include <vector>
#include <array>
#include <random>
#include "pbkdf2_hmac.h"
#include "SHA256.h"
#include "pbkdf2_hmac.cpp"

//HELPER FUNCTIONS
/**
 * turn key and password to 128 bit vector
 */
std::vector<uint8_t> stringTo128Bits(const std::string& input) {
    std::vector<uint8_t> bytes(input.begin(), input.end());

    if (bytes.size() > 16) {
        bytes.resize(16);
    } else if (bytes.size() < 16) {
        bytes.resize(16, 0);
    }

    return bytes;
}

/**
 * For converting key and password to hex
 */
std::string toHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (auto b : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

/**
 * for converting hex strings into 16 bit arrays for encryption
 */
std::array<uint8_t, 16> hexStringToArray16(const std::string& hex) {
    std::array<uint8_t, 16> arr{};
    size_t len = std::min<size_t>(hex.size(), 32);
    for (size_t i = 0; i < len / 2; ++i) {
        std::string byteStr = hex.substr(i * 2, 2);
        arr[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
    }
    return arr;
}

/**
 * s box
 */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/**
 * Multiply by 2 in GF(2^8) for mix columns
 */
static uint8_t xtime(uint8_t x) {
    if (x & 0x80) {
        return static_cast<uint8_t>((x << 1) ^ 0x1B);
    } else {
        return static_cast<uint8_t>(x << 1);
    }
}

/**
 * Multiply by 3 in GF(2^8) for mix columns
 */ 
static uint8_t mul3(uint8_t x) {
    return xtime(x) ^ x;
}









//AES FUNCTIONS
/**
 * substitution with s box
 */
static void SubBytes(std::array<uint8_t, 16>& s) {
    for (int i = 0; i < 16; ++i)
        s[i] = sbox[s[i]];
}

/**
 * shifts 2nd, 3rd, and 4th row accordingly
 */
static void ShiftRows(std::array<uint8_t, 16>& s) {
    std::array<uint8_t, 16> tmp = s;
    tmp[1]  = s[5];  tmp[5]  = s[9];  tmp[9]  = s[13]; tmp[13] = s[1];
    tmp[2]  = s[10]; tmp[6]  = s[14]; tmp[10] = s[2];  tmp[14] = s[6];
    tmp[3]  = s[15]; tmp[7]  = s[3];  tmp[11] = s[7];  tmp[15] = s[11];
    s = tmp;
}

/**
 * multiply columns with matrices
 */
static void MixColumns(std::array<uint8_t, 16>& s) {
    for (int i = 0; i < 4; ++i) {
        int c = i * 4;
        uint8_t a0 = s[c + 0];
        uint8_t a1 = s[c + 1];
        uint8_t a2 = s[c + 2];
        uint8_t a3 = s[c + 3];

        s[c + 0] = static_cast<uint8_t>(xtime(a0) ^ mul3(a1) ^ a2 ^ a3);
        s[c + 1] = static_cast<uint8_t>(a0 ^ xtime(a1) ^ mul3(a2) ^ a3);
        s[c + 2] = static_cast<uint8_t>(a0 ^ a1 ^ xtime(a2) ^ mul3(a3));
        s[c + 3] = static_cast<uint8_t>(mul3(a0) ^ a1 ^ a2 ^ xtime(a3));
    }
}

/**
 * mix round key with current state of plaintext
 */
static void AddRoundKey(std::array<uint8_t,16>& s, const uint8_t* rk) {
    for (int i = 0; i < 16; ++i)
        s[i] ^= rk[i];
}

/**
 * Encrypt function
 */
std::array<uint8_t,16> encrypt(const std::array<uint8_t,16>& input, const std::array<uint8_t,16>& key) {
    uint8_t roundKeys[176];
    std::array<uint8_t,16> state = input;
    AddRoundKey(state, roundKeys);

    //first 9 rounds
    for (int round = 1; round <= 9; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }

    //10th round
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + 160); 
    return state;
}

void aes128(std::string key, std::string password){
    // Convert to fixed 128-bit byte arrays
    std::vector<uint8_t> keyBytes = stringTo128Bits(key);
    std::vector<uint8_t> passBytes = stringTo128Bits(password);

    //getting random salt
    CryptoRandom randGen;
    std::vector<uint8_t> salt = randGen.GetSalt(16);

    //getting derived key from PBKDF2
    uint64_t iterations = 100000;
    size_t keyLength = 16; 
    std::vector<uint8_t> derivedKey = PBKDF2(passBytes, salt, iterations, keyLength);

    //converts to hex versions
    std::string hexKey = toHex(keyBytes);
    std::string hexPass = toHex(passBytes);

    //convert hex strings into 16-byte arrays
    std::array<uint8_t,16> keyArray = hexStringToArray16(hexKey);
    std::array<uint8_t,16> passArray = hexStringToArray16(hexPass);

    //encrypt
    std::array<uint8_t,16> encrypted = encrypt(passArray, keyArray);

    //test hex
    std::cout << hexKey << std::endl;
    std::cout << hexPass << std::endl;

    //show cipher text
    std::cout << "Ciphertext:  ";
    for (auto c : encrypted){
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    std::cout << "\n";
}

int main(){
    aes128("Thats my Kung Fu", "Two One Nine Two");
}