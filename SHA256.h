#include <iostream>
#include <vector>
#include <string>
#include <cstdint>

class SHA256 {
private:
    //outer is to hold multiple 512bit blocks from padded or preprocessed message
    std::vector<std::vector<uint8_t>> blocks; // Each block should be 512-bits (64 bytes), block vector has elements of 1-byte(8bit) so there should be 64 elements of the inner vector making 64bytes total in inner

public:
    void PreProcessMessage(const std::string& input) {
        blocks.clear(); 

        std::vector<uint8_t> msg_bytes(input.begin(), input.end()); //vector that takes a string and converts each character into 1-byte elements 

        // Prepend '1' bit (0x80)
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
        }//after this loop, msg_bytes will be multiple of 64 bytes in length, if short, just 64bytes

        // Split into 512-bit (64-byte) blocks
        for (size_t i = 0; i < msg_bytes.size(); i += 64) {//step by 64 as each chunk being process is 64 bytes
            std::vector<uint8_t> block(msg_bytes.begin() + i, msg_bytes.begin() + i + 64); //create a block and fill it with 64 bytes of msg_bytes  
            blocks.push_back(block); //push that block into last position of blocks vector
        }// after this, the message is fully divided into 512-bit (64-byte) blocks stored in 'blocks', length of message determines how many blocks  
    }

    //TODO impelement update function to increment data
    void update(const std::string& input){

    }

    //TODO implement digest function to get the 32 byte result
    std::vector<uint8_t> digest(){
        
    }
};
