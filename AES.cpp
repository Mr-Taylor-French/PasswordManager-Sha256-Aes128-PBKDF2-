#include <iostream>
#include <string>
#include <fstream>
#include <cstdint>
#include <vector>
#include <array>
#include <random>
#include <sstream>
#include <iomanip>
#include "pbkdf2_hmac.h"
#include "SHA256.h"

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
 * for converting hex array to string
 */
std::string hexArrayToString(const std::array<uint8_t, 16>& arr) {
    std::string result;
    for (auto byte : arr) {
        result += static_cast<char>(byte);
    }
    return result;
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
 * inverse s box
 */
static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
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

/**
 * Multiply by 9 in GF(2^8) for inverse mix columns
 */
static uint8_t mul9(uint8_t x) {
    return xtime(xtime(xtime(x))) ^ x;
}

/**
 * Multiply by 11 in GF(2^8) for inverse mix columns
 */
static uint8_t mul11(uint8_t x) {
    return xtime(xtime(xtime(x))) ^ xtime(x) ^ x;
}

/**
 * Multiply by 13 in GF(2^8) for inverse mix columns
 */
static uint8_t mul13(uint8_t x) {
    return xtime(xtime(xtime(x))) ^ xtime(xtime(x)) ^ x;
}

/**
 * Multiply by 14 in GF(2^8) for inverse mix columns
 */
static uint8_t mul14(uint8_t x) {
    return xtime(xtime(xtime(x))) ^ xtime(xtime(x)) ^ xtime(x);
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
 * inverse substitution with inverse s box
 */
static void InvSubBytes(std::array<uint8_t, 16>& s) {
    for (int i = 0; i < 16; ++i)
        s[i] = inv_sbox[s[i]];
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

/* Inverse ShiftRows (rotate rows right by offsets) */
static void InvShiftRows(std::array<uint8_t,16>& s) {
    std::array<uint8_t, 16> tmp = s;
    // Row 1: right rotate by 1
    tmp[1]  = s[13]; tmp[5]  = s[1];  tmp[9]  = s[5];  tmp[13] = s[9];
    // Row 2: right rotate by 2 (same as left rotate by 2)
    tmp[2]  = s[10]; tmp[6]  = s[14]; tmp[10] = s[2];  tmp[14] = s[6];
    // Row 3: right rotate by 3
    tmp[3]  = s[7];  tmp[7]  = s[11]; tmp[11] = s[15]; tmp[15] = s[3];
    // Row 0 stays the same
    tmp[0] = s[0]; tmp[4] = s[4]; tmp[8] = s[8]; tmp[12] = s[12];
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
 * MixColumns for decryption
 */
static void InvMixColumns(std::array<uint8_t,16>& s) {
    for (int i = 0; i < 4; ++i) {
        int c = i * 4;
        uint8_t a0 = s[c + 0];
        uint8_t a1 = s[c + 1];
        uint8_t a2 = s[c + 2];
        uint8_t a3 = s[c + 3];

        s[c + 0] = static_cast<uint8_t>(mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3));
        s[c + 1] = static_cast<uint8_t>(mul9(a0) ^ mul14(a1) ^ mul11(a2) ^ mul13(a3));
        s[c + 2] = static_cast<uint8_t>(mul13(a0) ^ mul9(a1) ^ mul14(a2) ^ mul11(a3));
        s[c + 3] = static_cast<uint8_t>(mul11(a0) ^ mul13(a1) ^ mul9(a2) ^ mul14(a3));
    }
}

/**
 * mix round key with current state of plaintext
 */
static void AddRoundKey(std::array<uint8_t,16>& s, const uint8_t* rk) {
    for (int i = 0; i < 16; ++i)
        s[i] ^= rk[i];
}

/* Key expansion for AES-128: fills 176-byte round key buffer from 16-byte key */
static void KeyExpansion(const uint8_t* key, uint8_t* roundKeys) {
    // Rcon values for AES-128
    const uint8_t Rcon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

    // First round key is the original key
    for (int i = 0; i < 16; ++i) roundKeys[i] = key[i];

    int bytesGenerated = 16;
    int rconIteration = 0;
    uint8_t temp[4];

    while (bytesGenerated < 176) {
        for (int i = 0; i < 4; ++i) temp[i] = roundKeys[bytesGenerated - 4 + i];

        if (bytesGenerated % 16 == 0) {
            // rotate
            uint8_t t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            // sub bytes
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            // Rcon
            temp[0] ^= Rcon[rconIteration];
            rconIteration++;
        }

        for (int i = 0; i < 4; ++i) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 16] ^ temp[i];
            bytesGenerated++;
        }
    }
}

/**
 * Encrypt function
 */
std::array<uint8_t,16> encrypt(const std::array<uint8_t,16>& input, const std::array<uint8_t,16>& key) {
    uint8_t roundKeys[176];
    // generate round keys from key
    KeyExpansion(key.data(), roundKeys);

    std::array<uint8_t,16> state = input;
    // initial AddRoundKey
    AddRoundKey(state, roundKeys);

    // first 9 rounds
    for (int round = 1; round <= 9; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }

    // 10th round (no MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + 160);
    return state;
}

/**
 * Decrypt function
 */
std::array<uint8_t,16> decrypt(const std::array<uint8_t,16>& input, const std::array<uint8_t,16>& key) {
    uint8_t roundKeys[176];
    KeyExpansion(key.data(), roundKeys);

    std::array<uint8_t,16> state = input;
    // initial AddRoundKey with last round key
    AddRoundKey(state, roundKeys + 160);

    // rounds 9..1
    for (int round = 9; round >= 1; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * 16);
        InvMixColumns(state);
    }

    // final round
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);
    return state;
}

/**
 * inverse AES function
 */
std::string aes128_decrypt(std::string key, std::array<uint8_t,16> cipherText){
    // Convert to fixed 128-bit byte array
    std::vector<uint8_t> keyBytes = stringTo128Bits(key);

    //converts to hex version
    std::string hexKey = toHex(keyBytes);

    //convert hex string into 16-byte array
    std::array<uint8_t,16> keyArray = hexStringToArray16(hexKey);

    //decrypt
    std::array<uint8_t,16> decrypted = decrypt(cipherText, keyArray);

    //show plain text
    // std::cout << "Decrypted Plaintext:  ";
    std::string decryptedString = hexArrayToString(decrypted);
    // std::cout << decryptedString << "\n";

    return decryptedString;
}

std::string aes128(std::string key, std::string password){
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
    // std::cout << hexKey << std::endl;
    // std::cout << hexPass << std::endl;

    //show cipher text
    // std::cout << "Ciphertext:  ";
    // for (auto c : encrypted){
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    // }
    // std::cout << "\n";

    std::string encPassword = hexArrayToString(encrypted);
    return encPassword;
    //aes128_decrypt(key, encrypted);
}

// CSV format: Website,Username,Password,Key
void writeToCSV(const std::string& filename, const std::string& website, 
                const std::string& username, const std::string& password, const std::string& key) {
    std::ofstream file;
    file.open(filename, std::ios::app);
    if (file.is_open()) {
        file <<  website << "," 
             << username << "," 
             << password << "," 
             << key << "\n";
        file.close();
    } else {
        std::cerr << "Unable to open file: " << filename << std::endl;
    }
}

void readFromCSV(const std::string& filename, const std::string& website, const std::string& username) {
    std::ifstream file(filename);
    if (file.is_open()) {
        std::string line;
        bool found = false;
        while (std::getline(file, line)) {
            std::istringstream ss(line);
            std::string site, user, password, key;

            std::getline(ss, site, ',');
            std::getline(ss, user, ',');
            std::getline(ss, password, ',');
            std::getline(ss, key, ',');

            password = aes128_decrypt(key, hexStringToArray16(toHex(std::vector<uint8_t>(password.begin(), password.end()))));

            if (site == website && user == username) {
                std::cout << "Password: " << password << "\n";
                //std::cout << "Key: " << key << "\n";
                found = true;
                break;
            }
        }
        file.close();
        if (!found) {
            std::cout << "No entry found for the given website and username.\n";
        }
    } else {
        std::cerr << "Unable to open file: " << filename << std::endl;
    }
}

int main(){
    //aes128("Thats my Kung Fu", "Two One Nine Two");

    int choice = 0;
    std::string website;
    std::string username;
    std::string filename = "passwords.csv";

    while (choice != 3) {
        std::cout << "Password Manager\n";
        std::cout << "1. Add Entry\n";
        std::cout << "2. View Entry\n";
        std::cout << "3. Exit\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;
        std::cin.ignore(); // to ignore the newline character after the integer input

        if (choice == 1) {
            std::string website, username, password, key;
            std::cout << "Enter Website: ";
            std::getline(std::cin, website);
            std::cout << "Enter Username: ";
            std::getline(std::cin, username);
            std::cout << "Enter Password: ";
            std::getline(std::cin, password);
            std::cout << "Enter Key: ";
            std::getline(std::cin, key);

            password = aes128(key, password); // Encrypt and display ciphertext

            writeToCSV(filename, website, username, password, key);
            std::cout << "Password added successfully!\n";

        } else if (choice == 2) {
            std::cout << "Website: ";
            std::cin >> website;
            std::cin.ignore(); // to ignore the newline character
            std::cout << "Username: ";
            std::cin >> username;
            std::cin.ignore(); // to ignore the newline character
            readFromCSV(filename, website, username);

        } else if (choice == 3) {
            std::cout << "Exiting...\n";

        } else {
            std::cout << "Invalid choice. Please try again.\n";
        }
    }

    return 0;
}