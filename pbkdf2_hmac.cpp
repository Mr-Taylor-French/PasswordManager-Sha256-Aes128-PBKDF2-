#include <iostream>
#include <string>
#include <cstdint>
#include <vector>
#include <random>
#include <algorithm>
#include "pbkdf2_hmac.h"
#include "SHA256.h"



/* Just if strings are getting used anywhere, why not keep it, before because the string to vec issue*/
void secure_wipe_string(std::string &s){//have to do this because compiler optimizations wont let you just do a fill,
	if (!s.empty()) {//if already empty, no need to wipe
		volatile char *p = &s[0];//idea is to make a volatile pointer to first of string(so no compiler optimization problems) then fill string with gargage data
		std::fill(p, p + s.size(), '\0');
	}
}

void secure_wipe_vec(std::vector<uint8_t> &vec){
	if (!vec.empty()){
		volatile uint8_t *p = &vec[0];
		std::fill(p, p + vec.size(), '\0');
	}
}

std::vector<uint8_t> HMAC_SHA256(const std::vector<uint8_t> &key, const std::vector<uint8_t> &text){//reference so whole thing is not copied, parameters are const in this func.
	std::vector<uint8_t> B = key;//the byte 'string' to use in these internal calculations
	SHA256 obj;
	if(B.size() > 64){//if key is longer than block size, errors will occur so hash it as doc says, you do it before the pad if cond. is hit so it can be padded to 64 length vector
		B = obj.hash(B);
	}
	if (B.size() < 64){//it needs to be padded with zero bytes here if not length of blocks used in hashing func.
		B.resize(64, 0x00); //this is better than a while loop with filling at the end of array, one vector size reallocation
									//instead of potentially many and one fill cycle instead of many, ofc no loop too
	}
	//first do the inner and outer pad byte repeat thing
	std::vector<uint8_t> inner_pad(64, 0x36);//number of elements, then the element
	std::vector<uint8_t> outer_pad(64, 0x5C);
	std::vector<uint8_t> B_xor_ipad, B_xor_opad;
	for (size_t i = 0; i < 64; i++){//both xor sections are processed in here as results dont change and same size loop
		B_xor_ipad.push_back(B[i] ^ inner_pad[i]);
		B_xor_opad.push_back(B[i] ^ outer_pad[i]);
	}
	secure_wipe_vec(inner_pad);
	secure_wipe_vec(outer_pad);
	for (size_t i = 0; i < text.size(); i++){//append text to B_xor_ipad,
		B_xor_ipad.push_back(text[i]);
	}

	std::vector<uint8_t> s_hash = obj.hash(B_xor_ipad);
	secure_wipe_vec(B_xor_ipad);

	for (size_t i = 0; i < s_hash.size(); i++){//append the first hash result to the xor_outer thing
		B_xor_opad.push_back(s_hash[i]);
	}
	secure_wipe_vec(s_hash);
	std::vector<uint8_t> result = obj.hash(B_xor_opad);//hash that result then we good
	secure_wipe_vec(B_xor_opad);
	return result;
}



void CryptoRandom::GetNewHMAC(){//just turns old hashed vector into a new hash then HMACs that again with a new salt array
	secure_wipe_vec(hmac_rand);
	hash_vec = sha_obj.hash(hash_vec);//as sha obj should still exist if new iv and salt are gotten, might as well use it again

	std::vector<uint8_t> rand_vec(64), XORvec;

	for (auto &b : rand_vec) b = static_cast<uint8_t>(rd()); //assigns the b, a byte to the vector with index b

	size_t limit = std::min(hash_vec.size(), rand_vec.size());
	for (size_t i = 0; i < limit; i++){
		XORvec.push_back(hash_vec[i] ^ rand_vec[i]);
	}
	hmac_rand = HMAC_SHA256(hash_vec, XORvec);
	if (hmac_rand.empty()){//just in case ig
		throw std::runtime_error(" hmac_rand cannot be empty");
	}
}

CryptoRandom::CryptoRandom(){/*constructor*/
	hash_vec.resize(64);
	for (auto &b : hash_vec) b = static_cast<uint8_t>(rd());
	hash_vec = sha_obj.hash(hash_vec);
	GetNewHMAC();
}


std::vector<uint8_t> CryptoRandom::GetSalt(size_t size){
	if (size == 0){
		throw std::runtime_error("Salt size cannot be less than or equal to zero");
	}
	std::vector<uint8_t> salt_vec(size);

	for (auto &b : salt_vec) b = static_cast<uint8_t>(rd()); //assigns the b, a byte to the vector with index b
	return salt_vec;
}
	
std::vector<uint8_t> CryptoRandom::GetIv(size_t size){//almost same as salt but makes sure to add no number used twice idea,
	std::vector<uint8_t> IV(size);
	if (size == 0){
		throw std::runtime_error("IV size or half_size cannot be less than or equal to zero");
	}
		
	for (size_t i = 0; i < size; i++){
		IV[i] = static_cast<uint8_t>(rd()) ^ hmac_rand[i % hmac_rand.size()]; //only some will be used, modulus so it can wrap around itself if iv > hmac_rand.size()
	}
	return IV;
}

CryptoRandom::~CryptoRandom() {
		secure_wipe_vec(hash_vec);
		secure_wipe_vec(hmac_rand);
}


uint64_t ceiling_func(uint64_t a, uint64_t b){//no need for another library which will get messy, simple way to do it
	return (a + b - 1) / b;
}

// INT: encode block index i as 4-octet big-endian vector
std::vector<uint8_t> INT(uint32_t i) {
    std::vector<uint8_t> bytes(4);
    bytes[0] = static_cast<uint8_t>((i >> 24) & 0xFF);
    bytes[1] = static_cast<uint8_t>((i >> 16) & 0xFF);
    bytes[2] = static_cast<uint8_t>((i >> 8) & 0xFF);
    bytes[3] = static_cast<uint8_t>(i & 0xFF);
    return bytes;
}

// F: the PBKDF2 block function: F(P, S, c, i) -> hLen-octet block
std::vector<uint8_t> F(const std::vector<uint8_t>& password,
                       const std::vector<uint8_t>& salt,
                       uint64_t iter_count,
                       uint32_t block_index) {
    const size_t hLen = 32; // HMAC-SHA256 output length
    if (iter_count == 0) throw std::runtime_error("iter_count must be > 0");

    // salt || INT(i)
    std::vector<uint8_t> salt_block = salt;
    std::vector<uint8_t> int_be = INT(block_index);
    salt_block.insert(salt_block.end(), int_be.begin(), int_be.end());

    // U1 = PRF(P, S || INT(i))
    std::vector<uint8_t> U = HMAC_SHA256(password, salt_block);
    if (U.size() != hLen) throw std::runtime_error("HMAC_SHA256 returned wrong size");

    std::vector<uint8_t> T = U; // T = U1 initially

    // U2..Uc
    for (uint64_t j = 1; j < iter_count; ++j) {
        U = HMAC_SHA256(password, U); // U_j = PRF(P, U_{j-1})
        if (U.size() != hLen) throw std::runtime_error("HMAC_SHA256 returned wrong size during iterations");
        for (size_t k = 0; k < hLen; ++k) {
            T[k] ^= U[k];
        }
    }

    // return T (hLen bytes)
    return T;
}

std::vector<uint8_t> PBKDF2(const std::vector<uint8_t> &password, const std::vector<uint8_t> &salt, const uint64_t iter_count, const size_t dklen){
	const int hlen = 32;//num of bytes from hashing function output
	uint64_t dklen_limit = ((4294967295ULL) * hlen);// number should be within 64bit range of unsigned numbers
	if (dklen > dklen_limit || password.empty() || salt.empty() || iter_count <= 0){//error check for parameter values, mess with salt if its not a vector!!!!!!!!!!!!!!@@@@@@@
		std::cerr << "dklen: " << dklen << ", it should be less than: " << dklen_limit << ". password length: " << password.size() << ", salt length/NUMBEEEER: " << salt.size()
		<< ", iteration_count: " << iter_count << ".\n";
		std::exit(EXIT_FAILURE);
	}

	SHA256 obj;
	std::vector<uint8_t> derived_key(32); //it should be 32byte key, each element 8bits/1byte ofc
	uint64_t l_ceil = ceiling_func(dklen, hlen);//number of byte blocks in final key, rounded up
	uint64_t r = dklen - ((l_ceil - 1) * hlen);// number of bytes in the last block
	
	std::vector<uint8_t> derivedKey;
    derivedKey.reserve(dklen);
    uint64_t hLen = 32; 
    uint64_t maxLen = ((1ULL << 32) - 1) * hLen;

    //checking length and throwing error
    if (dklen > maxLen) {
        throw std::runtime_error("derived key too long");
    }

    //For each block of the derived key apply the function F
    for(int i = 1; i <= l_ceil; i++){
        std::vector<uint8_t> T = F(password, salt, iter_count, i);
        derivedKey.insert(derivedKey.end(), T.begin(), T.end());
    }

    derivedKey.resize(dklen);
    return std::vector<uint8_t>(derivedKey.begin(), derivedKey.end());

}






