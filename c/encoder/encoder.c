/*
 * RecurSec Shellcode Encoder — Encodes and transforms shellcode payloads.
 *
 * Encoders:
 * - XOR with configurable key
 * - ROT-N byte rotation
 * - Base64 encoding/decoding
 * - Hex encoding/decoding
 * - Reverse byte order
 * - NULL-byte elimination (XOR-based)
 * - Alpha-numeric encoding
 *
 * Build: gcc -O2 -Wall -o encoder encoder.c
 * Usage: encoder <encode|decode> <method> <input_file> [key]
 *        encoder xor <input_file> <key_byte_hex>
 *        encoder base64 <input_file>
 *        encoder hex <input_file>
 *        encoder rot <input_file> <n>
 *        encoder null-free <input_file>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#define MAX_SIZE (1024 * 1024)  /* 1MB max shellcode */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Read entire file into buffer */
static long read_file(const char *path, unsigned char *buf, long max_size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open file: %s\n", path);
        return -1;
    }
    long n = fread(buf, 1, max_size, f);
    fclose(f);
    return n;
}

/* XOR encode/decode */
static void xor_encode(unsigned char *data, long size, unsigned char key) {
    for (long i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

/* Multi-byte XOR */
static void xor_multi(unsigned char *data, long size, const unsigned char *key, int key_len) {
    for (long i = 0; i < size; i++) {
        data[i] ^= key[i % key_len];
    }
}

/* ROT-N byte rotation */
static void rot_encode(unsigned char *data, long size, int n) {
    for (long i = 0; i < size; i++) {
        data[i] = (unsigned char)((data[i] + n) & 0xFF);
    }
}

/* Reverse byte order */
static void reverse_bytes(unsigned char *data, long size) {
    for (long i = 0; i < size / 2; i++) {
        unsigned char tmp = data[i];
        data[i] = data[size - 1 - i];
        data[size - 1 - i] = tmp;
    }
}

/* Base64 encode */
static long base64_encode(const unsigned char *input, long in_len, char *output) {
    long i, j = 0;
    for (i = 0; i < in_len - 2; i += 3) {
        output[j++] = b64_table[(input[i] >> 2) & 0x3F];
        output[j++] = b64_table[((input[i] & 0x3) << 4) | ((input[i+1] >> 4) & 0xF)];
        output[j++] = b64_table[((input[i+1] & 0xF) << 2) | ((input[i+2] >> 6) & 0x3)];
        output[j++] = b64_table[input[i+2] & 0x3F];
    }
    if (i < in_len) {
        output[j++] = b64_table[(input[i] >> 2) & 0x3F];
        if (i == in_len - 1) {
            output[j++] = b64_table[(input[i] & 0x3) << 4];
            output[j++] = '=';
        } else {
            output[j++] = b64_table[((input[i] & 0x3) << 4) | ((input[i+1] >> 4) & 0xF)];
            output[j++] = b64_table[(input[i+1] & 0xF) << 2];
        }
        output[j++] = '=';
    }
    output[j] = '\0';
    return j;
}

/* Hex encode */
static long hex_encode(const unsigned char *input, long in_len, char *output) {
    long j = 0;
    for (long i = 0; i < in_len; i++) {
        j += sprintf(output + j, "\\x%02x", input[i]);
    }
    output[j] = '\0';
    return j;
}

/* C array format */
static void c_array_format(const unsigned char *data, long size, const char *name) {
    printf("unsigned char %s[] = {\n  ", name);
    for (long i = 0; i < size; i++) {
        printf("0x%02x", data[i]);
        if (i < size - 1) printf(", ");
        if ((i + 1) % 12 == 0 && i < size - 1) printf("\n  ");
    }
    printf("\n};\n");
    printf("unsigned int %s_len = %ld;\n", name, size);
}

/* NULL-byte elimination via XOR with auto-key selection */
static unsigned char find_null_free_key(const unsigned char *data, long size) {
    for (int key = 1; key < 256; key++) {
        int has_null = 0;
        for (long i = 0; i < size; i++) {
            if ((data[i] ^ (unsigned char)key) == 0) {
                has_null = 1;
                break;
            }
        }
        if (!has_null) return (unsigned char)key;
    }
    return 0;  /* No single-byte key eliminates all nulls */
}

/* Print shellcode statistics */
static void print_stats(const unsigned char *data, long size) {
    int null_count = 0;
    int printable_count = 0;
    int freq[256] = {0};

    for (long i = 0; i < size; i++) {
        freq[data[i]]++;
        if (data[i] == 0) null_count++;
        if (isprint(data[i])) printable_count++;
    }

    printf("{\n");
    printf("  \"size\": %ld,\n", size);
    printf("  \"null_bytes\": %d,\n", null_count);
    printf("  \"printable_pct\": %.1f,\n", size > 0 ? (printable_count * 100.0 / size) : 0.0);
    printf("  \"null_free\": %s,\n", null_count == 0 ? "true" : "false");

    /* Entropy estimate */
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / size;
            entropy -= p * (log(p) / log(2.0));
        }
    }
    printf("  \"entropy\": %.2f\n", entropy);
    printf("}\n");
}

/* Print usage */
static void usage(const char *prog) {
    fprintf(stderr, "RecurSec Shellcode Encoder\n\n");
    fprintf(stderr, "Usage: %s <command> <input_file> [args...]\n\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  xor <file> <key_hex>       XOR encode (e.g., xor sc.bin 0x41)\n");
    fprintf(stderr, "  xor-multi <file> <key_str>  Multi-byte XOR\n");
    fprintf(stderr, "  rot <file> <n>              ROT-N byte rotation\n");
    fprintf(stderr, "  base64 <file>               Base64 encode\n");
    fprintf(stderr, "  hex <file>                  Hex encode (\\x format)\n");
    fprintf(stderr, "  carray <file> [name]        C array format\n");
    fprintf(stderr, "  reverse <file>              Reverse byte order\n");
    fprintf(stderr, "  null-free <file>            Auto-select XOR key to eliminate NULLs\n");
    fprintf(stderr, "  stats <file>                Print shellcode statistics\n");
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];
    const char *input_path = argv[2];

    unsigned char *buf = (unsigned char *)malloc(MAX_SIZE);
    char *outbuf = (char *)malloc(MAX_SIZE * 4);
    if (!buf || !outbuf) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    long size = read_file(input_path, buf, MAX_SIZE);
    if (size < 0) {
        free(buf);
        free(outbuf);
        return 1;
    }

    if (strcmp(command, "xor") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s xor <file> <key_hex>\n", argv[0]);
            free(buf); free(outbuf);
            return 1;
        }
        unsigned long key = strtoul(argv[3], NULL, 0);
        xor_encode(buf, size, (unsigned char)(key & 0xFF));
        fwrite(buf, 1, size, stdout);
        fprintf(stderr, "XOR encoded %ld bytes with key 0x%02lx\n", size, key & 0xFF);

    } else if (strcmp(command, "xor-multi") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s xor-multi <file> <key_string>\n", argv[0]);
            free(buf); free(outbuf);
            return 1;
        }
        int key_len = strlen(argv[3]);
        xor_multi(buf, size, (unsigned char *)argv[3], key_len);
        fwrite(buf, 1, size, stdout);
        fprintf(stderr, "Multi-byte XOR encoded %ld bytes with %d-byte key\n", size, key_len);

    } else if (strcmp(command, "rot") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s rot <file> <n>\n", argv[0]);
            free(buf); free(outbuf);
            return 1;
        }
        int n = atoi(argv[3]);
        rot_encode(buf, size, n);
        fwrite(buf, 1, size, stdout);
        fprintf(stderr, "ROT-%d encoded %ld bytes\n", n, size);

    } else if (strcmp(command, "base64") == 0) {
        long out_len = base64_encode(buf, size, outbuf);
        printf("%s\n", outbuf);
        fprintf(stderr, "Base64 encoded: %ld -> %ld bytes\n", size, out_len);

    } else if (strcmp(command, "hex") == 0) {
        hex_encode(buf, size, outbuf);
        printf("%s\n", outbuf);
        fprintf(stderr, "Hex encoded %ld bytes\n", size);

    } else if (strcmp(command, "carray") == 0) {
        const char *name = argc > 3 ? argv[3] : "shellcode";
        c_array_format(buf, size, name);

    } else if (strcmp(command, "reverse") == 0) {
        reverse_bytes(buf, size);
        fwrite(buf, 1, size, stdout);
        fprintf(stderr, "Reversed %ld bytes\n", size);

    } else if (strcmp(command, "null-free") == 0) {
        unsigned char key = find_null_free_key(buf, size);
        if (key == 0) {
            fprintf(stderr, "No single-byte XOR key eliminates all NULL bytes\n");
            free(buf); free(outbuf);
            return 1;
        }
        fprintf(stderr, "Auto-selected NULL-free XOR key: 0x%02x\n", key);
        xor_encode(buf, size, key);
        fwrite(buf, 1, size, stdout);
        /* Also print decoder stub info */
        fprintf(stderr, "Decoder stub: for (int i=0; i<len; i++) buf[i] ^= 0x%02x;\n", key);

    } else if (strcmp(command, "stats") == 0) {
        print_stats(buf, size);

    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        usage(argv[0]);
        free(buf); free(outbuf);
        return 1;
    }

    free(buf);
    free(outbuf);
    return 0;
}
