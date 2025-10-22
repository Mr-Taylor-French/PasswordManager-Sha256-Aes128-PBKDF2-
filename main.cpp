#include <iostream> 
#include <string>
#include <cassert>
#include "SHA256.h"


std::string HMAC_SHA256(std::string key, std::string password) {
    const int blockSize = 64;
    SHA256 hash;

    if(key.size() > blockSize){
        key = hash.hash_print(key);   
    }
    std::vector<uint8_t> keyBlock(blockSize, 0x00);
    for (size_t i = 0; i < key.size(); ++i) {
        keyBlock[i] = static_cast<uint8_t>(key[i]);
    }

    // Create inner and outer pads
    std::vector<uint8_t> o_key_pad(blockSize);
    std::vector<uint8_t> i_key_pad(blockSize);
    for (int i = 0; i < blockSize; ++i) {
        o_key_pad[i] = keyBlock[i] ^ 0x5c;
        i_key_pad[i] = keyBlock[i] ^ 0x36;
    }

    // Convert i_key_pad to string
    std::string i_pad_str(i_key_pad.begin(), i_key_pad.end());
    std::string inner_hash = hash.hash_print(i_pad_str + password);

    // Convert inner_hash string to bytes for outer hash
    std::string o_pad_str(o_key_pad.begin(), o_key_pad.end());
    std::string hmac = hash.hash_print(o_pad_str + inner_hash);

    return hmac;
}


/*
 * Function PBKDF2
 * @param password, salt, hash, length
 * @param c is iterations
 * @return string derived key
 * */
 
std::string PBKDF2(std::string password, std::string salt, int c, SHA256 hash, int length){
    int hash_len = 32; // SHA256 produces 32 bytes
    int blocks = (length + hash_len - 1) / hash_len;
    std::string derived_key;

    for (int i = 1; i <= blocks; ++i) {
        // Salt + INT(i) in big endian
        std::string salt_block = salt;
        salt_block += static_cast<char>((i >> 24) & 0xFF);
        salt_block += static_cast<char>((i >> 16) & 0xFF);
        salt_block += static_cast<char>((i >> 8) & 0xFF);
        salt_block += static_cast<char>(i & 0xFF);

        std::string U = HMAC_SHA256(password, salt_block);
        std::string T = U;

        for (int j = 1; j < c; ++j) {
            U = HMAC_SHA256(password, U);
            for (size_t k = 0; k < T.size(); ++k) {
                T[k] ^= U[k];
            }
        }

        derived_key += T;
    }

    return derived_key.substr(0, length);
}


int main() { 

    std::string key = "thisisthekey";
    std::string password = "!@#$%^&*()_+-={}[]|:;<>,.?/~`";
    SHA256 obj;

    std::string hmac = HMAC_SHA256(key, password);
    std::cout << "HMAC: " << hmac << std::endl;
    
    std::string dk = PBKDF2(password, "salt123", 1000, obj, 32);
    std::cout << "Derived key: ";
    for (unsigned char c : dk) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(uint8_t)c;
    }
    std::cout << std::endl;
    
    std::string test_vec = obj.hash_print(password);
    std::cout << test_vec << std::endl;
    
    return 0; 
}
