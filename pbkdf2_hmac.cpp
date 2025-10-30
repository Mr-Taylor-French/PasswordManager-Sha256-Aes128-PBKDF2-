#include <iostream>
#include <string>
#include <cstdint>
#include <vector>
#include "SHA256.h"
#include <random>
#include <algorithm>

void secure_wipe_string(std::string &s){//have to do this because compiler optimizations wont let you just do a fill,
	if (!s.empty()) {//if already empty, no need to wipe
		volatile char *p = &s[0];
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
	if(B.empty()){// reminder, c ifs evaluate to true if the statement itself is true, no need for B.empty() == true
		throw std::runtime_error("Key cannot be empty, its being copied to a temporary value if that give any more info on problem");
	}
	if(B.size() > 64){//if key is longer than block size, errors will occur so hash it as doc says, you do it before the pad if cond. is hit so it can be padded to 64 length vector
		std::string t (B.begin(), B.end());
		B.clear();//clear B
		B = obj.hash(t);
		secure_wipe_string(t);
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
	std::string s (B_xor_ipad.begin(), B_xor_ipad.end());//works because it defines the iterators for it and chars are 8bits, other vector decimal types wont work
	secure_wipe_vec(B_xor_ipad);
	std::vector<uint8_t> s_hash = obj.hash(s);
	secure_wipe_string(s);

	for (size_t i = 0; i < s_hash.size(); i++){//append the first hash result to the xor_outer thing
		B_xor_opad.push_back(s_hash[i]);
	}
	std::string p (B_xor_opad.begin(), B_xor_opad.end());
	secure_wipe_vec(B_xor_opad);
	std::vector<uint8_t> result = obj.hash(p);//hash that result then we good
	secure_wipe_string(p);
	return result;
}


class CryptoRandom{
private:
	SHA256 sha_obj;
	std::vector<uint8_t> hash_vec;
	std::vector<uint8_t> hmac_rand;
	std::random_device rd; //an object to use to get randomish bytes, each rd() returns an unsigned int. note, doesnt matter creating new rd objs that rd() will get a new thing each time not deterministic

	void GetNewHMAC(){//just turns old hashed vector into a new hash then HMACs that again with a new salt array
		std::string t (hash_vec.begin(), hash_vec.end());
		secure_wipe_vec(hmac_rand);
		secure_wipe_vec(hash_vec);
		hash_vec = sha_obj.hash(t);//as sha obj should still exist if new iv and salt are gotten, might as well use it again
		secure_wipe_string(t);
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
public:
	CryptoRandom(){/*constructor*/	
		std::string seed_str(32, ' ');
		for (auto &b : seed_str) b = static_cast<unsigned char>(rd()); //assigns the b, a byte to the string with index b
		hash_vec = sha_obj.hash(seed_str);
		secure_wipe_string(seed_str);
		GetNewHMAC();
	}

	/*Disable copy construction, copy assignment, and std:move()*/
	CryptoRandom(const CryptoRandom&) = delete;
	CryptoRandom& operator=(const CryptoRandom&) = delete;
	CryptoRandom(CryptoRandom&&) = delete;

	std::vector<uint8_t> GetSalt(size_t size){
		if (size == 0){
			throw std::runtime_error("Salt size cannot be less than or equal to zero");
		}
		std::vector<uint8_t> salt_vec(size);

		for (auto &b : salt_vec) b = static_cast<uint8_t>(rd()); //assigns the b, a byte to the vector with index b
		return salt_vec;
	}
	
	std::vector<uint8_t> GetIv(size_t size){//almost same as salt but makes sure to add no number used twice idea,
		std::vector<uint8_t> IV(size);
		if (size == 0){
			throw std::runtime_error("IV size or half_size cannot be less than or equal to zero");
		}
		
		for (size_t i = 0; i < size; i++){
			IV[i] = static_cast<uint8_t>(rd()) ^ hmac_rand[i % hmac_rand.size()]; //only some will be used, modulus so it can wrap around itself if iv > hmac_rand.size()
		}
		GetNewHMAC();//for if next time IV is needed, get a new random hmac vec in this for nonce reasons, og hmac for this GetIv is alredy made the first time obj is constructed
		return IV;
	}
	~CryptoRandom() {
		secure_wipe_vec(hash_vec);
		secure_wipe_vec(hmac_rand);
	}
};

void print_hex(const std::vector<uint8_t>& data) {
	for (auto b : data){
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
	}
	std::cout << std::dec << "\n";
}


/*
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
}
*/
int main(){
	try {
		std::cout << "=== CryptoRandom Functionality Test ===\n";
	
		CryptoRandom cr;

		//Test salt generation
		auto salt1 = cr.GetSalt(16);
		auto salt2 = cr.GetSalt(16);
		std::cout << "Salt 1 (16 bytes): "; print_hex(salt1);
		std::cout << "Salt 2 (16 bytes): "; print_hex(salt2);

		if (salt1 == salt2)
			std::cout << "ERROR: Salt values should differ\n";
		else
			std::cout << "Salt values differ as expected\n";

		//Test IV generation
		auto iv1 = cr.GetIv(16);
		auto iv2 = cr.GetIv(16);
		std::cout << "IV 1 (16 bytes):	 "; print_hex(iv1);
		std::cout << "IV 2 (16 bytes):	 "; print_hex(iv2);

		if (iv1 == iv2)
			std::cout << "ERROR: IV values should differ\n";
		else
			std::cout << "IV values differ as expected\n";

		//Test different sizes
		auto salt32 = cr.GetSalt(32);
		auto iv32 = cr.GetIv(32);
		std::cout << "Salt 32 bytes size: " << salt32.size() << "\n";
		std::cout << "IV 32 bytes size:   " << iv32.size() << "\n";

		//Test invalid input
		try {
			cr.GetSalt(0);
			std::cout << "ERROR: Expected exception for salt size 0\n";
		} catch (const std::exception& e) {
			std::cout << "Expected exception for salt size 0: " << e.what() << "\n";
		}

		try {
			cr.GetIv(0);
			std::cout << "ERROR: Expected exception for IV size 0\n";
		} catch (const std::exception& e) {
			std::cout << "Expected exception for IV size 0: " << e.what() << "\n";
		}

		std::cout << "=== All basic functionality tests completed ===\n";
	}
	catch (const std::exception &e) {
		std::cerr << "Unhandled exception: " << e.what() << "\n";
	}

	return 0;
}








