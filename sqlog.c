#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <unistd.h>

#include "sqlog.h"

static unsigned char g_key[LOG_AES_KEY_LEN];
static FILE *g_log_fp = NULL;
static int g_log_index = 0;
static char g_current_log_filename[512] = {0};
static unsigned int g_log_msg_num = 0;

// Converts hex string to binary buffer
static int hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len)
{
    for (size_t i = 0; i < bin_len; ++i)
    {
        if (sscanf(&hex[i * 2], "%2hhx", &bin[i]) != 1)
            return -1;
    }
    return 0;
}

// Returns current log file size
static long get_file_size(const char *filename)
{
    struct stat st;
    if (stat(filename, &st) != 0)
        return 0;
    return st.st_size;
}

// Builds log filename with optional index suffix

static void build_log_filename(int index, char *out, size_t out_len)
{
    if (index == 0)
    {
        snprintf(out, out_len, "%s%s", LOG_FILE_PATH, LOG_FILE_BASE_NAME);
    }
    else
    {
        snprintf(out, out_len, "%s%s.%03d", LOG_FILE_PATH, LOG_FILE_BASE_NAME, index);
    }
}

// Find the highest existing log file index: dump1090.log.001, .002, ...
static int get_max_log_index()
{
    DIR *dir = opendir(LOG_FILE_PATH);
    if (!dir)
        return 0;

    struct dirent *entry;
    int max_index = 0;
    while ((entry = readdir(dir)) != NULL)
    {
        int idx = 0;
        if (sscanf(entry->d_name, LOG_FILE_BASE_NAME ".%03d", &idx) == 1)
        {
            if (idx > max_index)
                max_index = idx;
        }
    }
    closedir(dir);
    return max_index;
}

// Rename current log to .NNN and start fresh
static int rotate_log_file_if_needed(size_t new_entry_size)
{
    long size = get_file_size(g_current_log_filename);
    if (size + new_entry_size < LOG_FILE_SIZE)
        return 0;

    // Close current file
    if (g_log_fp)
    {
        fclose(g_log_fp);
        g_log_fp = NULL;
    }

    // Find next index
    int max_idx = get_max_log_index();
    char rotated_name[512];
    snprintf(rotated_name, sizeof(rotated_name),
             LOG_FILE_PATH LOG_FILE_BASE_NAME ".%03d", max_idx + 1);

    // Rename current log to rotated
    printf("%s ren [%s] ==> [%s]\n", __func__, g_current_log_filename, rotated_name);
    rename(g_current_log_filename, rotated_name);

    // Open new log file as dump1090.log
    snprintf(g_current_log_filename, sizeof(g_current_log_filename),
             "%s%s", LOG_FILE_PATH, LOG_FILE_BASE_NAME);

    g_log_fp = fopen(g_current_log_filename, "wb");
    printf("%s --> %s, %p\n", __func__, g_current_log_filename, g_log_fp);
    return g_log_fp ? 0 : -1;
}

// Opens a new log file based on current index
static int open_new_log_file()
{
    build_log_filename(g_log_index, g_current_log_filename, sizeof(g_current_log_filename));
    g_log_fp = fopen(g_current_log_filename, "ab");
    printf("%s --> %s\n", __func__, g_current_log_filename);
    return g_log_fp != NULL ? 0 : -1;
}

// Initializes encryption key and opens log file
int InitLogFromFile(const char *key_file)
{
    FILE *kf = fopen(key_file, "r");
    if (!kf)
    {
        printf("Can't find log key %s\n", key_file);
        return -1;
    }

    char key_hex[LOG_AES_KEY_LEN * 2 + 1] = {0};
    if (!fgets(key_hex, sizeof(key_hex), kf))
    {
        fclose(kf);
        return -1;
    }
    fclose(kf);

    if (strlen(key_hex) < LOG_AES_KEY_LEN * 2)
        return -1;

    if (hex_to_bin(key_hex, g_key, LOG_AES_KEY_LEN) != 0)
        return -1;

    g_log_index = 0;
    if (open_new_log_file() != 0)
        return -1;

    return 0;
}

static int base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len)
{
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines

    BIO_write(b64, in, in_len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &buffer_ptr);

    if (buffer_ptr->length >= out_len)
    {
        BIO_free_all(b64);
        return -1;
    }

    memcpy(out, buffer_ptr->data, buffer_ptr->length);
    out[buffer_ptr->length] = '\0';

    BIO_free_all(b64);
    return 0;
}

// Writes an encrypted log message to the current file
int WriteLog(const char *message)
{
    if (!g_log_fp)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[LOG_AES_GCM_IV_LEN];
    unsigned char tag[LOG_AES_GCM_TAG_LEN];
    unsigned char ciphertext[1024];
    int outlen = 0, tmplen = 0;

    g_log_msg_num = (g_log_msg_num + 1) % 1000000;
    char numbered_msg[2048];
    snprintf(numbered_msg, sizeof(numbered_msg), "%06u: %s", g_log_msg_num, message);

    RAND_bytes(iv, sizeof(iv));

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, g_key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &outlen, (unsigned char *)numbered_msg, strlen(numbered_msg));
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen);
    outlen += tmplen;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
    EVP_CIPHER_CTX_free(ctx);

    // Compose [IV][CIPHERTEXT][TAG]
    unsigned char combined[sizeof(iv) + outlen + sizeof(tag)];
    memcpy(combined, iv, sizeof(iv));
    memcpy(combined + sizeof(iv), ciphertext, outlen);
    memcpy(combined + sizeof(iv) + outlen, tag, sizeof(tag));

    // Base64 encode
    char encoded[2048];
    if (base64_encode(combined, sizeof(combined), encoded, sizeof(encoded)) != 0)
    {
        return -1;
    }

    // Before writing, check if rotation is needed
    if (rotate_log_file_if_needed(strlen(encoded)) != 0)
    {
        // If we can't open new log file.
        // FIXME later
        return -1;
    }

    // Write to file (1 line per entry)
    fprintf(g_log_fp, "%s\n", encoded);
    fflush(g_log_fp);

    printf("[%p] %s\n", g_log_fp, numbered_msg);

    return 0;
}

#if 1
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

int SqLog(int log_level, const char *format, ...)
{
    char msg_buffer[SQLOG_BUFFER_SIZE];
    char final_buffer[SQLOG_BUFFER_SIZE];
    const char *level_str = NULL;
    va_list args;

    switch ((LOG_LEVEL)log_level)
    {
    case LOG_LEVEL_F:
        level_str = "[F] ";
        break;
    case LOG_LEVEL_E:
        level_str = "[E] ";
        break;
    case LOG_LEVEL_W:
        level_str = "[W] ";
        break;
    case LOG_LEVEL_I:
        level_str = "[I] ";
        break;
    case LOG_LEVEL_D:
        level_str = "[D] ";
        break;
    default:
        level_str = "[?] ";
        break;
    }

    // Format the user message
    va_start(args, format);
    vsnprintf(msg_buffer, sizeof(msg_buffer), format, args);
    va_end(args);

    // Get timestamp (yyyy-mm-dd hh:mm:ss.mmm)
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);

    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    int ms = tv.tv_usec / 1000;

    // Compose final_buffer: "2025-06-06 14:30:12.123 [I] message..."
    int prefix_len = snprintf(final_buffer, sizeof(final_buffer), "%s.%03d %s", time_str, ms, level_str);

    size_t msg_len = strlen(msg_buffer);
    if ((size_t)prefix_len + msg_len < sizeof(final_buffer))
    {
        // Entire message fits
        memcpy(final_buffer + prefix_len, msg_buffer, msg_len + 1);
    }
    else if ((size_t)prefix_len < sizeof(final_buffer))
    {
        // Truncate message
        size_t copy_len = sizeof(final_buffer) - prefix_len - 1;
        memcpy(final_buffer + prefix_len, msg_buffer, copy_len);
        final_buffer[sizeof(final_buffer) - 1] = '\0';
    }
    else
    {
        // Timestamp + level too long
        final_buffer[sizeof(final_buffer) - 1] = '\0';
    }

    // Split into chunks of SQLOG_LINE_MAX and call WriteLog
    size_t len = strlen(final_buffer);
    size_t offset = 0;

    while (offset < len)
    {
        size_t chunk_size = SQLOG_LINE_MAX;
        if (offset + chunk_size > len)
        {
            chunk_size = len - offset;
        }

        char chunk[SQLOG_LINE_MAX + 1];
        memcpy(chunk, final_buffer + offset, chunk_size);
        chunk[chunk_size] = '\0';

        WriteLog(chunk);
        offset += chunk_size;
    }

    return 0;
}
#else
int SqLog(int log_level, const char *format, ...)
{
    char msg_buffer[SQLOG_BUFFER_SIZE];
    char final_buffer[SQLOG_BUFFER_SIZE];
    const char *level_str = NULL;
    va_list args;

    switch ((LOG_LEVEL)log_level)
    {
    case LOG_LEVEL_F:
        level_str = "[F] ";
        break;
    case LOG_LEVEL_E:
        level_str = "[E] ";
        break;
    case LOG_LEVEL_W:
        level_str = "[W] ";
        break;
    case LOG_LEVEL_I:
        level_str = "[I] ";
        break;
    case LOG_LEVEL_D:
        level_str = "[D] ";
        break;
    default:
        level_str = "[?] ";
        break;
    }

    va_start(args, format);
    vsnprintf(msg_buffer, sizeof(msg_buffer), format, args);
    va_end(args);

    // Compose final_buffer with level_str and msg_buffer safely
    size_t prefix_len = strlen(level_str);
    size_t msg_len = strlen(msg_buffer);

    if (prefix_len + msg_len < sizeof(final_buffer))
    {
        // Both fit
        memcpy(final_buffer, level_str, prefix_len);
        memcpy(final_buffer + prefix_len, msg_buffer, msg_len + 1); // including '\0'
    }
    else if (prefix_len < sizeof(final_buffer))
    {
        // Prefix fits, message truncated
        memcpy(final_buffer, level_str, prefix_len);
        size_t copy_len = sizeof(final_buffer) - prefix_len - 1;
        memcpy(final_buffer + prefix_len, msg_buffer, copy_len);
        final_buffer[sizeof(final_buffer) - 1] = '\0';
    }
    else
    {
        // Prefix itself too long, truncate prefix only
        memcpy(final_buffer, level_str, sizeof(final_buffer) - 1);
        final_buffer[sizeof(final_buffer) - 1] = '\0';
    }

    // 이후에 final_buffer를 256바이트 단위로 나눠 WriteLog 호출하는 코드를 계속 사용
    size_t len = strlen(final_buffer);
    size_t offset = 0;

    while (offset < len)
    {
        size_t chunk_size = SQLOG_LINE_MAX;
        if (offset + chunk_size > len)
        {
            chunk_size = len - offset;
        }

        char chunk[SQLOG_LINE_MAX + 1];
        memcpy(chunk, final_buffer + offset, chunk_size);
        chunk[chunk_size] = '\0';

        WriteLog(chunk);
        offset += chunk_size;
    }

    return 0;
}
#endif

void SqLog_LogStart(int argc, char *argv[])
{
#if 0
    // 1. 시간 구하기
    time_t now = time(NULL);
    char timebuf[64];
    struct tm *tm_info = localtime(&now);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
#endif
    // 2. 실행 파일 절대 경로 구하기
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len != -1)
    {
        exe_path[len] = '\0';
    }
    else
    {
        strncpy(exe_path, argv[0], sizeof(exe_path));
        exe_path[sizeof(exe_path) - 1] = '\0';
    }

    // 3. 명령행 전체 만들기
    char cmdline[4096] = {0};
    for (int i = 0; i < argc; i++)
    {
        strcat(cmdline, argv[i]);
        if (i < argc - 1)
            strcat(cmdline, " ");
    }

    // 로그 출력 (예: 파일 대신 stdout)
    SqLog_I("Newly started\n");
    SqLog_I("Executable Path: %s\n", exe_path);
    SqLog_I("Command Line: %s\n", cmdline);
}
