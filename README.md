# ChaCha20
Implementation of the ChaCha cipher in c++

## Usage
```cpp
#include  "project/ChaCha.h"

...
// Create a 256 bit long key.
char  buffer[] = "Hello, World!";
ChaCha::Key256 key = { SECRET_KEY };
ChaCha::ChaCha20 encryptor(key);

auto  cipher = encrytpor.EncryptData(buffer, sizeof(buffer), 0);
auto  recoverd = encrytpor.DecryptData(cipher.get(), sizeof(buffer), 0);

std::cout  <<  recoverd.get() <<  std::endl;

```
