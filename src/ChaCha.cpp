#include "project/ChaCha.h"
#include <iostream>
#include <algorithm>

// Rotate left, translates to a <<< b
#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

namespace ChaCha
{
    ChaCha20::ChaCha20(Key256 key, int rounds) : key(key), rounds(rounds)
    {
    }

    std::array<char, BLOCK_SIZE_BYTES> ChaCha20::GenerateKeyBlock(long long position, long long nonce)
    {
        std::array<char, BLOCK_SIZE_BYTES> block = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        int matrix[4][4] = {
            {0x65787061, 0x6e642033, 0x322d6279, 0x7465206b}, // The constatnts, "expand 32 by te k" in ascii.
            {this->key[0], this->key[1], this->key[2], this->key[3]},
            {this->key[4], this->key[5], this->key[6], this->key[7]},
            {static_cast<int>(position), static_cast<int>(position >> 32), static_cast<int>(nonce), static_cast<int>(nonce >> 32)}};

        for (int i = 0; i < this->rounds; i++)
        {
            // Perform the querter round on the columns
            this->QuerterRound(matrix[0][0], matrix[1][0], matrix[2][0], matrix[3][0]);
            this->QuerterRound(matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1]);
            this->QuerterRound(matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2]);
            this->QuerterRound(matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3]);

            // Perform the querter round on the diagonals
            this->QuerterRound(matrix[0][0], matrix[1][1], matrix[2][2], matrix[3][3]);
            this->QuerterRound(matrix[0][1], matrix[1][2], matrix[2][3], matrix[3][0]);
            this->QuerterRound(matrix[0][2], matrix[1][3], matrix[2][0], matrix[3][1]);
            this->QuerterRound(matrix[0][3], matrix[1][0], matrix[2][1], matrix[3][2]);
        }

        std::copy_n(reinterpret_cast<char *>(&matrix), BLOCK_SIZE_BYTES, block.data());

        return block;
    }

    void ChaCha20::QuerterRound(int &a, int &b, int &c, int &d)
    {
        a += b;
        d ^= a;
        d = ROTL(d, 16);
        c += d;
        b ^= c;
        b = ROTL(b, 12);
        a += b;
        d ^= a;
        d = ROTL(d, 8);
        c += d;
        b ^= c;
        b = ROTL(b, 7);
    }

    std::unique_ptr<char> ChaCha20::EncryptData(const char *data, size_t size, long long startPosition, std::optional<std::vector<long long> *> nonces)
    {
        // Create the encrypted buffer with the padding.
        char *encrypted = new char[size];

        int blocksCount = std::ceil((float)size / BLOCK_SIZE_BYTES);
        std::default_random_engine generator;
        std::uniform_int_distribution<long long> distribution(LONG_LONG_MIN, LONG_LONG_MAX);

        for (int i = 0; i < blocksCount; i++)
        {
            long long nonce = nonces.has_value() ? distribution(generator) : 0;

            auto key = this->GenerateKeyBlock(++startPosition, nonce);

            // Encrypt the block
            for (int j = 0; j < BLOCK_SIZE_BYTES && i * BLOCK_SIZE_BYTES + j < size; j++)
            {
                encrypted[i * BLOCK_SIZE_BYTES + j] = data[i * BLOCK_SIZE_BYTES + j] ^ key.data()[j];
            }

            if (nonces.has_value())
                nonces.value()->push_back(nonce);
        }

        return std::unique_ptr<char>(encrypted);
    }

    std::unique_ptr<char> ChaCha20::DecryptData(const char *data, size_t size, long long startPosition, std::optional<std::vector<long long> *> nonces)
    {
        auto decrypted = new char[size];
        int blocksCount = std::ceil((float)size / BLOCK_SIZE_BYTES);

        for (int i = 0; i < blocksCount; i++)
        {
            long long nonce = nonces.has_value() ? nonces.value()->at(i) : 0;

            auto key = this->GenerateKeyBlock(++startPosition, nonce);

            for (int j = 0; j < BLOCK_SIZE_BYTES && i * BLOCK_SIZE_BYTES + j < size; j++)
            {
                decrypted[i * BLOCK_SIZE_BYTES + j] = data[i * BLOCK_SIZE_BYTES + j] ^ key.data()[j];
            }
        }

        return std::unique_ptr<char>(decrypted);
    }

    ChaCha20::~ChaCha20() {}
}