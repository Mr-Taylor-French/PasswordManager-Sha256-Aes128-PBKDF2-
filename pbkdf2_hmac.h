#pragma once

#include <iostream>
#include <string>
#include <cstdint>
#include <vector>
#include <random>
#include <algorithm>
#include "SHA256.h"


void secure_wipe_string(std::string &s);
void secure_wipe_vec(std::vector<uint8_t> &vec);

std::vector<uint8_t> HMAC_SHA256(const std::vector<uint8_t> &key, const std::vector<uint8_t> &text);


class CryptoRandom {
private:
	SHA256 sha_obj;
	std::vector<uint8_t> hash_vec;
	std::vector<uint8_t> hmac_rand;
	std::random_device rd;

	void GetNewHMAC();

public:
	CryptoRandom();  // Constructor
	~CryptoRandom(); // Destructor

	// Disable copy/move
	CryptoRandom(const CryptoRandom&) = delete;
	CryptoRandom& operator=(const CryptoRandom&) = delete;
	CryptoRandom(CryptoRandom&&) = delete;
	CryptoRandom& operator=(CryptoRandom&&) = delete;


	std::vector<uint8_t> GetSalt(size_t size);
	std::vector<uint8_t> GetIv(size_t size);
};


std::vector<uint8_t> PBKDF2(const std::vector<uint8_t> &password, const std::vector<uint8_t> &salt, const uint64_t iter_count, const size_t dklen);
