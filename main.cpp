#include <iostream> 
#include <string>
#include <cassert>
#include <cmath>
#include "SHA256.h"


<<<<<<< Updated upstream
/**
 * Function HMAC_SHA256
 * @param key, message
 * @return message authentication code
 */
std::string HMAC_SHA256(std::string key, std::string password) {
    std::vector<uint8_t> keyBlock(64, 0x00);
=======

std::string HMAC_SHA256(const std::string& password, std::vector<uint8_t> key) {
    const int blockSize = 64;
>>>>>>> Stashed changes
    SHA256 hash;

    // Step 1: Hash key if longer than block size
    if (key.size() > blockSize) {
        std::string hashedKey = hash.hash_print(std::string(key.begin(), key.end()));
        key.assign(hashedKey.begin(), hashedKey.end());
    }

    // Step 2: Pad key to block size
    std::vector<uint8_t> keyBlock(blockSize, 0x00);
    for (size_t i = 0; i < key.size(); ++i) {
        keyBlock[i] = key[i];
    }

    // Step 3: Create inner and outer pads
    std::vector<uint8_t> o_key_pad(blockSize);
    std::vector<uint8_t> i_key_pad(blockSize);
    for (int i = 0; i < blockSize; ++i) {
        o_key_pad[i] = keyBlock[i] ^ 0x5c;
        i_key_pad[i] = keyBlock[i] ^ 0x36;
    }

    // Step 4: Perform HMAC
    std::string i_pad_str(i_key_pad.begin(), i_key_pad.end());
    std::string inner_hash = hash.hash_print(i_pad_str + password);

    std::string o_pad_str(o_key_pad.begin(), o_key_pad.end());
    std::string hmac = hash.hash_print(o_pad_str + inner_hash);

    return hmac;
}


<<<<<<< Updated upstream
=======

>>>>>>> Stashed changes
/**
 * Function PBKDF2
 * @param password, salt, hash, length
 * @param c is iterations
 * @return string derived key
 */
<<<<<<< Updated upstream
std::string PBKDF2(std::string password, std::string salt, int c, SHA256 hash, int length){
    //TODO implement PBKDF2
}

=======
 
std::string PBKDF2(const std::string& password, const std::string& salt, int c, int dkLen){
    std::vector<uint8_t> derivedKey;
    derivedKey.reserve(dkLen);
    uint64_t hLen = 32; 
    uint64_t maxLen = ((1ULL << 32) - 1) * hLen;

    //checking length and throwing error
    if (dkLen > maxLen) {
        throw std::runtime_error("derived key too long");
    }

    //"Let l be the number of hLen-octet blocks in the derived key, rounding up, and let r be the number of octets in the last block" from the document 
    int l = std::ceil(static_cast<double>(dkLen) / hLen);
    int r = dkLen - (1 - 1) * hLen;

    //For each block of the derived key apply the function F
    for(int i = 1; i <= l; i++){
        std::vector<uint8_t> T = F(password, salt, c, i);
        derivedKey.insert(derivedKey.end(), T.begin(), T.end());
    }

    derivedKey.resize(dkLen);
    return std::string(derivedKey.begin(), derivedKey.end());

}

/**
 * Function F for PBKDF2 repeated hashing loop
 * @param password, salt,
 * @param c is for iteraions
 * @param i is for block index
 * @return one derived key block
 */
std::vector<uint8_t> F(const std::string& password, const std::string& salt, int c, int i){
    //build salt by adding salt before the block index
    std::vector<uint8_t> saltBytes(salt.begin(), salt.end());
    std::vector<uint8_t> intBytes = INT(i);
    saltBytes.insert(saltBytes.end(), intBytes.begin(), intBytes.end());

    // U1 = PRF(P, S || INT(i))
    std::string U1 = HMAC_SHA256(password, saltBytes);

    // creating first block of the DK 
    std::vector<uint8_t> T(U1.begin(), U1.end());
    std::vector<uint8_t> U_prev = T;

    //adding the blocks and taking the first octents to create the DK
    for (int j = 2; j <= c; j++) {
        //U_c = PRF (P, U_{c-1})
        std::string Uc = HMAC_SHA256(password, U_prev);

        //looping and grabbing first octants
        for (size_t k = 0; k < T.size(); k++) {
            T[k] ^= static_cast<uint8_t>(Uc[k]);
        }

        U_prev.assign(Uc.begin(), Uc.end());
    }

    return T;

};

/**
 * Function INT for F which turns the block index i into a four octent encoding of i
 * @param i
 * @return four octent encoding of i
 */
std::vector<uint8_t> INT(int i) {
    std::vector<uint8_t> bytes(4);
    bytes[0] = (i >> 24) & 0xFF;  
    bytes[1] = (i >> 16) & 0xFF;
    bytes[2] = (i >> 8) & 0xFF;
    bytes[3] = i & 0xFF; 
    return bytes;
}


>>>>>>> Stashed changes




int main() { 

    std::string key = "thisisthekey";
    std::string password = "HelloWorld!";
    SHA256 hash;

    HMAC_SHA256(key, password);
    std::cout << password;

    return 0; 
}