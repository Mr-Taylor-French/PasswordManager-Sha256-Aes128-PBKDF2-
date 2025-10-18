#include <iostream> 
#include <string>
#include <cassert>
#include "SHA256.h"


/*
 

 
 

std::string HMAC_SHA256(std::string key, std::string password) {
    std::vector<uint8_t> keyBlock(64, 0x00);
    SHA256 hash;

    if(key.size() > 64){
        hash.encodeMessage(key);   
    }
    //TODO implement the rest of HMAC
    return password;
}



 * Function PBKDF2
 * @param password, salt, hash, length
 * @param c is iterations
 * @return string derived key
 
std::string PBKDF2(std::string password, std::string salt, int c, SHA256 hash, int length){
    //TODO implement PBKDF2
}
*/




int main() { 

    std::string key = "thisisthekey";
    std::string password = "!@#$%^&*()_+-={}[]|:;<>,.?/~`";
    SHA256 obj;

    //HMAC_SHA256(key, password);
    
    
    std::string test_vec = obj.hash_print(password);
    std::cout << test_vec << std::endl;
    
    

    return 0; 
}
