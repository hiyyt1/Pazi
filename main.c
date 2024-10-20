/**
 * @file main.c
 * @brief This file contains functions for file encryption and decryption using OpenSSL.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define SALT_SIZE 8
#define KEY_SIZE 32
#define IV_SIZE 16

/**
 * @brief Prints OpenSSL errors to stderr.
 */
void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

/**
 * @brief Derives encryption key and IV from password and salt using OpenSSL.
 * 
 * @param password The user's password.
 * @param salt Salt to add randomness.
 * @param key The derived key (output).
 * @param iv The derived IV (output).
 * @return 1 if successful, 0 if failed.
 */
int derive_key_from_password(const char *password, unsigned char *salt, unsigned char *key, unsigned char *iv) {
    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, (unsigned char *)password, strlen(password), 1, key, iv)) {
        return 0;
    }
    return 1;
}

/**
 * @brief Encrypts the specified file using a password.
 * 
 * @param filename The name of the file to encrypt.
 * @param password The password to use for encryption.
 * @return 1 if successful, 0 if failed.
 */
int encrypt_file(const char *filename, const char *password) {
    FILE *input = fopen(filename, "rb");
    if (!input) {
        perror("File open error");
        return 0;
    }

    char output_filename[256];
    snprintf(output_filename, sizeof(output_filename), "%s.enc", filename);
    FILE *output = fopen(output_filename, "wb");
    if (!output) {
        perror("File open error");
        fclose(input);
        return 0;
    }

    unsigned char salt[SALT_SIZE], key[KEY_SIZE], iv[IV_SIZE];
    if (!RAND_bytes(salt, SALT_SIZE)) {
        handle_errors();
    }

    fwrite("Salted__", 1, 8, output);  // Write Salted__ signature
    fwrite(salt, 1, SALT_SIZE, output);  // Write salt

    if (!derive_key_from_password(password, salt, key, iv)) {
        handle_errors();
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handle_errors();
    }

    unsigned char buffer[1024], ciphertext[1024 + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
    int len, ciphertext_len;

    while ((len = fread(buffer, 1, sizeof(buffer), input)) > 0) {
        if (!EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, len)) {
            handle_errors();
        }
        fwrite(ciphertext, 1, ciphertext_len, output);
    }

    if (!EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertext_len)) {
        handle_errors();
    }
    fwrite(ciphertext, 1, ciphertext_len, output);

    EVP_CIPHER_CTX_free(ctx);
    fclose(input);
    fclose(output);

    return 1;
}

/**
 * @brief Decrypts the specified file using a password.
 * 
 * @param filename The name of the file to decrypt.
 * @param password The password to use for decryption.
 * @return 1 if successful, 0 if failed.
 */
int decrypt_file(const char *filename, const char *password) {
    FILE *input = fopen(filename, "rb");
    if (!input) {
        perror("File open error");
        return 0;
    }

    unsigned char signature[8], salt[SALT_SIZE], key[KEY_SIZE], iv[IV_SIZE];
    fread(signature, 1, 8, input);
    if (memcmp(signature, "Salted__", 8) != 0) {
        fprintf(stderr, "Invalid file format\n");
        fclose(input);
        return 0;
    }
    fread(salt, 1, SALT_SIZE, input);

    if (!derive_key_from_password(password, salt, key, iv)) {
        handle_errors();
    }

    char output_filename[256];
    strncpy(output_filename, filename, strlen(filename) - 4);
    output_filename[strlen(filename) - 4] = '\0';  // Remove ".enc"
    FILE *output = fopen(output_filename, "wb");
    if (!output) {
        perror("File open error");
        fclose(input);
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handle_errors();
    }

    unsigned char buffer[1024], plaintext[1024 + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
    int len, plaintext_len;

    while ((len = fread(buffer, 1, sizeof(buffer), input)) > 0) {
        if (!EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, buffer, len)) {
            handle_errors();
        }
        fwrite(plaintext, 1, plaintext_len, output);
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext, &plaintext_len)) {
        handle_errors();
    }
    fwrite(plaintext, 1, plaintext_len, output);

    EVP_CIPHER_CTX_free(ctx);
    fclose(input);
    fclose(output);

    return 1;
}

/**
 * @brief Main function to process arguments and call encryption or decryption functions.
 * 
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, 1 on error.
 */
int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <encrypt|decrypt> <filename> <password>\n", argv[0]);
        return 1;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    const char *mode = argv[1];
    const char *filename = argv[2];
    const char *password = argv[3];

    if (strcmp(mode, "encrypt") == 0) {
        if (!encrypt_file(filename, password)) {
            fprintf(stderr, "Encryption failed\n");
            return 1;
        }
        printf("File encrypted successfully: %s.enc\n", filename);
    } else if (strcmp(mode, "decrypt") == 0) {
        if (!decrypt_file(filename, password)) {
            fprintf(stderr, "Decryption failed\n");
            return 1;
        }
        printf("File decrypted successfully: %s\n", filename);
    } else {
        fprintf(stderr, "Invalid mode. Use 'encrypt' or 'decrypt'.\n");
        return 1;
    }

    return 0;
}
