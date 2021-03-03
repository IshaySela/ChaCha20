#include "project/ChaCha.h"
#include <iostream>
#include <vector>

#pragma comment(lib, ".\\build\\bin\\chachalib.a")

int main()
{
    ChaCha::Key256 key = {1,2,3,4,5,6,7,8};
    char buffer[] = "Hello, World!";
    std::vector<long long> nonces;

    ChaCha::ChaCha20 encrytpor(key);
    auto cipher = encrytpor.EncryptData(buffer, sizeof(buffer), 0, &nonces);
    auto recoverd = encrytpor.DecryptData(cipher.get(), sizeof(buffer), 0, &nonces);

    std::cout << recoverd.get() << std::endl;
}
