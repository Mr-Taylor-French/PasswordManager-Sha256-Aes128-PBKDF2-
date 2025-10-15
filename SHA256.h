#include <iostream>
#include <vector>
#include <string>
#include <cstdint>

class SHA256 {
private:
    //outer blocks is to hold multiple 512bit blocks from preprocessed message
    std::vector<std::vector<uint8_t>> blocks; // Each block should be 512-bits (64 bytes), block vector has elements of 1-byte(8bit), there should be 64 elements of the inner vector making 64bytes total in inner

    //even though values are derived by fancy math functions, same for round constants btw, values are still used as 32 bit integers
    std::vector<uint32_t> hash_constants = { 
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    }; //each hash constant is 32 bits, theres 8 * 4bytes so 32bytes total space 
    std::vector<uint32_t> round_constants = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    }; //each round constant is 32 bits, theres 64 * 4bytes, so 256bytes total

public:
    void PreProcessMessage(const std::string& input) { //first part of this algorithm, takes the input and preprocesses it
        blocks.clear(); 

        std::vector<uint8_t> msg_bytes(input.begin(), input.end()); //vector that takes a string and converts each character into 1-byte elements 

        // append '1' bit (0x80)
        msg_bytes.push_back(0x80); 

        // Pad with zeros until length = 56 (mod 64)
        while ((msg_bytes.size() % 64) != 56) {
            msg_bytes.push_back(0x00);
        }
        
        // Append the original message length at the end of the message vector as a 64-bit big-endian integer,  
        uint64_t bit_len = static_cast<uint64_t>(input.size()) * 8; //compute input string length, if str = ABC, 3 bytes * 8 = 24 bits, static cast of 64 makes it 64bits, just adds leading zeros to make sure its represented as 64 bit
        for (int i = 7; i >= 0; --i) {
            uint8_t byte_to_extract = (bit_len >> (i * 8)) & 0xFF; //at i = 7, shifts the length 56 bits to the right, then you & it to just get that byte(last 8 bits)
            msg_bytes.push_back(byte_to_extract); 
        }//after this loop, msg_bytes will be multiple of 64 bytes in length, if short enough, just 64bytes

        // Split into 512-bit (64-byte) blocks
        for (size_t i = 0; i < msg_bytes.size(); i += 64) {//step by 64 as each chunk being process is 64 bytes
            std::vector<uint8_t> block(msg_bytes.begin() + i, msg_bytes.begin() + i + 64); //create a block, each block is 1byte   
            blocks.push_back(block); //push that block into last position of blocks vector, blocks should have multiple of 64 bytes, 1 byte blocks 
        }// after this, the message is fully divided into 512-bit (64-byte) blocks stored in 'blocks', length of message determines how many blocks, if short only one 512bit block is used
    }

    std::vector<uint32_t> message_schedule(const std::vector<uint8_t>& block){ 
        /*this will process one block of blocks, and create schedule for compression of that one 64 byte block, the other blocks if there are any, will use their own message schedule and compression,
        take block and put them in vector of 32 bit words/elements, 4 blocks to each word, block being 1 byte, 
        */
        //first 16 words are from 64 byte block
        std::vector<uint32_t> message_words;
        for (size_t i = 0; i < 16; i++){
            //the idea here is, take 4 bytes from 64 byte block, b[0], b[1], b[2], b[3] and pack them into a 32-bit(4byte) word, put that into message_words vector
            //first byte of word(static_cast<uint32_t>(block[i*4]), that just makes sure its a 32 bit num, shifted 3 bytes left, each thing or'ed to combine it, next shifted 2 bytes left, etc
            uint32_t word = 
                (static_cast<uint32_t>(block[i*4]) << 24) |
                (static_cast<uint32_t>(block[i*4 + 1]) << 16) |
                (static_cast<uint32_t>(block[i*4 + 2]) << 8) |
                (static_cast<uint32_t>(block[i*4 + 3]));
            message_words.push_back(word);
        }
    }


    //TODO impelement update function to increment data, not sure what this is for, input should be constant by the time it hits sha256
    void update(const std::string& input){
    }

    
    //TODO implement digest function to get the 32 byte result
    std::vector<uint8_t> digest(){
        
    }
};
