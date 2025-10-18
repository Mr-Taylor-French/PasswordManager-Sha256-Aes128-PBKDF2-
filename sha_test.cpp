#include <iostream>
#include <cassert>
#include <string>
#include "SHA256.h" // Ensure your SHA256 class is included

int main() {
    SHA256 obj;

	//Standard empty string
	assert(obj.hash_print("") == "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");

	//Simple string
	assert(obj.hash_print("abc") == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");

	//Longer string (from NIST test vectors)
	assert(obj.hash_print("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") == "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1");

	//One million a's (tests performance and large inputs)
	assert(obj.hash_print(std::string(1000000, 'a')) == "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0");

	//Classic pangram
	assert(obj.hash_print("The quick brown fox jumps over the lazy dog") == "D7A8FBB307D7809469CA9ABCB0082E4F8D5651E46D3CDB762D02D0BF37C9E592");

	//Pangram with period
	assert(obj.hash_print("The quick brown fox jumps over the lazy dog.") == "EF537F25C895BFA782526529A9B63D97AA631564D5D789C2B765448C8635FB6C");

	//Single character
	assert(obj.hash_print("a") == "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB");

	//Numbers only
	assert(obj.hash_print("1234567890") == "C775E7B757EDE630CD0AA1113BD102661AB38829CA52A6422AB782862F268646");

	//Special characters
	assert(obj.hash_print("!@#$%^&*()_+-={}[]|:;<>,.?/~`") == "64192E06FD03A054A8F7A478ADFED5B15EFFE6F3ECC24DF06DF143CC1D45B7AB");

	std::cout << "The SHA-256 test vectors passed, good shit dog" << std::endl;
}
