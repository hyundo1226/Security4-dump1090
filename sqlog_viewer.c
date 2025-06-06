#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "sqlog.h"

// Base64 디코딩 함수
static int base64_decode(const char *in, unsigned char *out, size_t *out_len)
{
    BIO *bio, *b64;
    int decoded_len;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(in, -1);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // 개행 제거

    decoded_len = BIO_read(bio, out, *out_len);
    if (decoded_len < 0)
    {
        BIO_free_all(bio);
        return -1;
    }

    *out_len = decoded_len;
    BIO_free_all(bio);
    return 0;
}

// hex -> binary 변환
static int hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len)
{
    for (size_t i = 0; i < bin_len; ++i)
    {
        if (sscanf(&hex[i * 2], "%2hhx", &bin[i]) != 1)
            return -1;
    }
    return 0;
}

static int load_key(unsigned char *key_out)
{
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s%s", LOG_KEY_FILE_PATH, LOG_KEY_FILE_NAME);

    FILE *kf = fopen(key_path, "r");
    if (!kf)
    {

        fprintf(stderr, "Failed to load AES key from %s\n", key_path);
        return -1;
    }

    char hex_key[LOG_AES_KEY_LEN * 2 + 1] = {0};
    if (!fgets(hex_key, sizeof(hex_key), kf))
    {
        fclose(kf);
        return -1;
    }
    fclose(kf);

    if (strlen(hex_key) < LOG_AES_KEY_LEN * 2)
        return -1;

    return hex_to_bin(hex_key, key_out, LOG_AES_KEY_LEN);
}

// Decrypts a GCM-encrypted log entry
static int decrypt_gcm(const unsigned char *key,
                       const unsigned char *data,
                       size_t data_len,
                       char *plaintext_out,
                       size_t plaintext_max)
{
    (void)plaintext_max; // Suppress unused parameter warning

    if (data_len < LOG_AES_GCM_IV_LEN + LOG_AES_GCM_TAG_LEN)
        return -1;

    const unsigned char *iv = data;
    const unsigned char *ciphertext = data + LOG_AES_GCM_IV_LEN;
    size_t ciphertext_len = data_len - LOG_AES_GCM_IV_LEN - LOG_AES_GCM_TAG_LEN;
    const unsigned char *tag = data + LOG_AES_GCM_IV_LEN + ciphertext_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen = 0, tmplen = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, LOG_AES_GCM_IV_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, (unsigned char *)plaintext_out, &outlen, ciphertext, ciphertext_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, LOG_AES_GCM_TAG_LEN, (void *)tag);

    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext_out + outlen, &tmplen) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // Decryption failed (tag mismatch)
    }

    outlen += tmplen;
    plaintext_out[outlen] = '\0';

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int main(int argc, char *argv[])
{
    unsigned char key[LOG_AES_KEY_LEN];

    if (load_key(key) != 0)
    {
        return 1;
    }

    // Determine which log file to read
    char filename[512];
    if (argc >= 2)
    {
        strncpy(filename, argv[1], sizeof(filename) - 1);
        filename[sizeof(filename) - 1] = '\0';
    }
    else
    {
        snprintf(filename, sizeof(filename), "%s%s", LOG_FILE_PATH, LOG_FILE_BASE_NAME);
    }

    printf("Reading log file: %s\n", filename);

    FILE *fp = fopen(filename, "r");
    if (!fp)
    {
        fprintf(stderr, "Failed to open log file: %s\n", filename);
        return 1;
    }

    char line[4096];
    unsigned char decoded[2048];
    char plaintext[2048];
    size_t decoded_len;

    while (fgets(line, sizeof(line), fp))
    {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0'; // remove newline

        decoded_len = sizeof(decoded);
        if (base64_decode(line, decoded, &decoded_len) != 0)
        {
            fprintf(stderr, "[!] Failed to base64-decode line\n");
            continue;
        }

        if (decrypt_gcm(key, decoded, decoded_len, plaintext, sizeof(plaintext)) != 0)
        {
            fprintf(stderr, "[!] Failed to decrypt line\n");
            continue;
        }

        printf("%s", plaintext);
    }

    fclose(fp);
    return 0;
}
