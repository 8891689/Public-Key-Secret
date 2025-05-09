/*Author: 8891689
 *https://github.com/8891689
 * Assist in creation ：ChatGPT / Gemini
 * Modified: Simplified for public key format conversion only.
 * Compile: gcc pkconvert.c -O3 -march=native -o pkconvert libsecp256k1.a
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h> // For isspace

// Use the official secp256k1 library header
#include <secp256k1.h>

/* 辅助函数声明 */
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len);
void bin2hex(const uint8_t *bin, size_t bin_len, char *hex);
void trim_whitespace(char *str); // Helper to remove leading/trailing whitespace

/*
 * 修剪字符串首尾的空白字符
 */
void trim_whitespace(char *str) {
    char *end;

    // trim leading whitespace
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) { // All spaces?
        *str = 0;
        return;
    }

    // trim trailing whitespace
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator
    *(end + 1) = 0;
}


/* 将 hex 字符串转换为二进制数据 */
// Note: This assumes `bin` buffer is large enough (e.g., 33 or 65 bytes).
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len == 0 || hex_len % 2 != 0) return -1;
    if (bin_len < hex_len / 2) return -1;

    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02hhx", &byte) != 1) { // Use %hhx for uint8_t
            return -1;
        }
        bin[i] = (uint8_t)byte;
    }
    return 0;
}

/* 将二进制数据转换为 hex 字符串 */
// Note: This assumes `hex` buffer is large enough (e.g., 66 or 130 bytes + 1).
void bin2hex(const uint8_t *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + i * 2, "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0';
}

// Function to process a single public key string
int process_pubkey(secp256k1_context *ctx, const char *pubkey_hex_input, int output_format, FILE *output_file) {
    size_t hex_len = strlen(pubkey_hex_input);

    // Validate input hex length
    if (hex_len != 66 && hex_len != 130) {
        fprintf(stderr, "Error: Invalid public key hex length (%zu) for input '%s'. Must be 66 (compressed) or 130 (uncompressed).\n", hex_len, pubkey_hex_input);
        return -1; // Indicate error
    }

    uint8_t pub_bin_input[65]; // Max size for uncompressed key bytes (65)
    size_t pub_bin_input_len = hex_len / 2;

    // Convert input hex to binary bytes
    if (hex2bin(pubkey_hex_input, pub_bin_input, pub_bin_input_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex format for input '%s'.\n", pubkey_hex_input);
        return -1; // Indicate error
    }

    // Parse public key bytes using libsecp256k1
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pub_bin_input, pub_bin_input_len)) {
        fprintf(stderr, "Error: Failed to parse public key (not on curve?) for input '%s'.\n", pubkey_hex_input);
        return -1; // Indicate error
    }

    // Serialize public key to the requested format
    uint8_t pub_out_bytes[65]; // Max size
    size_t pub_out_len = sizeof(pub_out_bytes);
    if (!secp256k1_ec_pubkey_serialize(ctx, pub_out_bytes, &pub_out_len, &pubkey, output_format)) {
        fprintf(stderr, "Error: Failed to serialize public key for input '%s'.\n", pubkey_hex_input);
        return -1; // Indicate error
    }

    // Convert serialized bytes back to hex for output
    char pub_out_hex[131]; // Max size
    bin2hex(pub_out_bytes, pub_out_len, pub_out_hex);

    // Output the result
    if (output_file) {
        fprintf(output_file, "%s\n", pub_out_hex);
    } else {
        printf("%s\n", pub_out_hex);
    }

    return 0; // Indicate success
}


int main(int argc, char **argv) {
    FILE *input_file = NULL;
    FILE *output_file = NULL;
    const char *input_arg = NULL;
    int output_format = SECP256K1_EC_COMPRESSED; // Default output format is compressed
    bool is_single_key_input = false;

    // --- Argument Parsing ---
    // Usage cases:
    // 1. ./pkconvert <public_key_hex>
    // 2. ./pkconvert <public_key_hex> -u  (or -c, but -c is default)
    // 3. ./pkconvert <input_file> <output_file>
    // 4. ./pkconvert <input_file> <output_file> -u (or -c)

    if (argc < 2 || argc > 4) {
        fprintf(stderr, "Usage 1: %s <public_key_hex> [-u|-c]\n", argv[0]);
        fprintf(stderr, "  <public_key_hex>: Compressed (66 chars) or uncompressed (130 chars) public key hex string.\n");
        fprintf(stderr, "  -u: Output uncompressed public key.\n");
        fprintf(stderr, "  -c: Output compressed public key (default).\n");
        fprintf(stderr, "Usage 2: %s <input_file> <output_file> [-u|-c]\n", argv[0]);
        fprintf(stderr, "  <input_file>: File containing public key hex strings, one per line.\n");
        fprintf(stderr, "  <output_file>: File to write the converted public key hex strings.\n");
        fprintf(stderr, "  -u: Output uncompressed public keys.\n");
        fprintf(stderr, "  -c: Output compressed public keys (default).\n");
        return 1;
    }

    // Determine input source and output destination
    if (argc == 2 || argc == 3) { // Case 1 or 2: Single key input
        input_arg = argv[1];
        is_single_key_input = true;
        // Check for format flag in argc == 3
        if (argc == 3) {
             if (strcmp(argv[2], "-u") == 0) {
                output_format = SECP256K1_EC_UNCOMPRESSED;
            } else if (strcmp(argv[2], "-c") == 0) {
                output_format = SECP256K1_EC_COMPRESSED; // Explicitly set, though it's the default
            } else {
                 fprintf(stderr, "Error: Invalid option '%s'. Use -u or -c.\n", argv[2]);
                 return 1;
            }
        }
    } else { // Case 3 or 4: File input/output
        // argc == 3 or 4
        const char *input_filename = argv[1];
        const char *output_filename = argv[2];

        input_file = fopen(input_filename, "r");
        if (!input_file) {
            perror("Error opening input file");
            return 1;
        }

        output_file = fopen(output_filename, "w");
        if (!output_file) {
            perror("Error opening output file");
            fclose(input_file);
            return 1;
        }

        // Check for format flag in argc == 4
        if (argc == 4) {
            if (strcmp(argv[3], "-u") == 0) {
                output_format = SECP256K1_EC_UNCOMPRESSED;
            } else if (strcmp(argv[3], "-c") == 0) {
                output_format = SECP256K1_EC_COMPRESSED; // Explicitly set
            } else {
                 fprintf(stderr, "Error: Invalid option '%s'. Use -u or -c.\n", argv[3]);
                 fclose(input_file);
                 fclose(output_file);
                 return 1;
            }
        }
    }

    // Initialize secp256k1 context
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY); // Only need verify context for parsing/serializing
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create secp256k1 context.\n");
        if (input_file) fclose(input_file);
        if (output_file) fclose(output_file);
        return 1;
    }

    // --- Process Input ---
    if (is_single_key_input) {
        process_pubkey(ctx, input_arg, output_format, output_file);
    } else {
        // Process file line by line
        char line[256]; // Buffer for reading lines
        int line_num = 0;
        while (fgets(line, sizeof(line), input_file)) {
            line_num++;
            trim_whitespace(line); // Remove leading/trailing whitespace

            // Skip empty lines
            if (strlen(line) == 0) {
                continue;
            }

            // Process the line as a public key hex string
            // process_pubkey prints errors internally
            process_pubkey(ctx, line, output_format, output_file);
        }
    }


    // --- Cleanup ---
    secp256k1_context_destroy(ctx);
    if (input_file) fclose(input_file);
    if (output_file) fclose(output_file);

    return 0;
}
