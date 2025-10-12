#include <iostream>
#include <vector>
#include <string>
#include <cstdint>

class SHA256 {
private:
    std::vector<std::vector<uint8_t>> blocks; // Each block is 512-bits (64 bytes)

public:
    void encodeMessage(const std::string& input) {
        blocks.clear();

        std::vector<uint8_t> msg_bytes(input.begin(), input.end());

        // Prepend '1' bit (0x80)
        msg_bytes.push_back(0x80);

        // Pad with zeros until length = 56 (mod 64)
        while ((msg_bytes.size() % 64) != 56) {
            msg_bytes.push_back(0x00);
        }

        // Append the original message length at the end of the message block as a 64-bit big-endian integer
        uint64_t bit_len = static_cast<uint64_t>(input.size()) * 8;
        for (int i = 7; i >= 0; --i) {
            msg_bytes.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));
        }

        // Split into 512-bit (64-byte) blocks
        for (size_t i = 0; i < msg_bytes.size(); i += 64) {
            std::vector<uint8_t> block(msg_bytes.begin() + i, msg_bytes.begin() + i + 64);
            blocks.push_back(block);
        }
    }

    //TODO impelement update function to increment data
    void update(const std::string& input){

    }

    //TODO implement digest function to get the 32 byte result
    std::vector<uint8_t> digest(){
        
    }
};