#pragma once
#include <string>
#include <array>
#include <vector>
#include <cmath>
#include <random>
#include <climits>
#include <optional>
#include <memory>
#include <functional>

#define BLOCK_SIZE_BYTES 32UL
#define BLOCK_SIZE_INT 8UL
#define BLOCK_SIZE_64_BIT 4UL


namespace ChaCha
{
    using Key256 = std::array<int, 8>;
    using PositionGenerator = std::function<long long(int)>;
    using NonceGenerator = std::function<long long(int)>;

    class ChaCha20
    {
    private:
        Key256 key;
        int rounds;
        /**
         * @brief Perform the querter round function on the 4 integers.
        */
        void QuerterRound(int &a, int &b, int &c, int &d);

    public:
        /**
         * @brief Create a new ChaCha256 object.
         * @param key The key to encrypt with.
         * @param rounds The amound of rounds to perform. default is 10.
        */
        ChaCha20(Key256 key, int rounds = 10);
        ~ChaCha20();

        /**
         * @brief Create a new psuedorandom key block.
         * @param position The position of the block.
         * @param nonce A number that is used once per generated key.
         * @returns The generated 512 bits long key.
        */
        std::array<char, BLOCK_SIZE_BYTES> GenerateKeyBlock(long long position, long long nonce);

        /**
         * @brief Encrypt the data and return the encrypted data. Every time a block is genereted a new random nonce is created and pushed into the vector.
         * @param data The buffer to encrypt.
         * @param size The size of the buffer.
         * @param startPositions The starting position for the position argument to GenerateKeyBlock. Every time a new block is generated this argument is increased by 1.
         * @param nonces An optional pointer to a vector that the nonces will be pushed to. By default is an empty optinal. If the nonces vector is empty, 0 will be used as the nonce for all blocks.
         * @return The encrypted data.
        */
        std::unique_ptr<char> EncryptData(const char *data, size_t size, long long startPositions, std::optional<std::vector<long long>*> nonces = std::nullopt);
        
        /**
         * @brief Encrypt the data and return a pointer to the encrypted data. Before a new block is encrypted, positionGenerator and nonceGenerator are be called,
         * and their return value is used as the nonce and the position.
         * @param data The buffer to encrypt.
         * @param size The size of the buffer.
         * @param positionGenerator A function that recives the block index and returns the position of the block.
         * @param nonceGenerator A function that recives the block index and returns the nonce of the block. The function must implement a way to store the created nonces.
         * @returns The encrypted data.
        */
        std::unique_ptr<char> EncryptData(const char* data, size_t size, PositionGenerator positionGenerator, NonceGenerator nonceGenerator);
        
        /**
         * @brief Decrypt the data given by recreating the keys using the starting position and nonces.
         * @param data The buffer to decrypt.
         * @param size The size of the buffer.
         * @param startPositions The starting position for the position argument to GenerateKeyBlock. Every time a new block is generated this argument is increased by 1.
         * @param nonces An optional vector of nonces to use. if the parameter is empty, use 0 instead.
         * @return The decrypted data.
        */
        std::unique_ptr<char> DecryptData(const char* data, size_t size, long long startPosition, std::optional<std::vector< long long>*> nonces = std::nullopt);
    };

}