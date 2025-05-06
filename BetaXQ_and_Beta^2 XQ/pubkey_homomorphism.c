// 作者：8891689
// gcc pubkey_homomorphism.c libsecp256k1.a -lgmp -Wall -Wextra -O3 -o pubkey_homomorphism
// 計算 secp256k1 公鑰的 6 個相關點 (原始、否定、乘以 Beta、乘以 Beta 的否定、乘以 Beta^2、乘以 Beta^2 的否定)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <gmp.h>
#include <secp256k1.h>

// secp256k1 曲線的階 N
// N = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
const char* SECP256K1_N_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
// secp256k1 Endomorphism beta scalar
const char* SECP256K1_BETA_HEX = "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee";

// 幫助函數：將十六進制字符串轉換為字節數組
bool hex_to_bytes(const char *hex, unsigned char *bytes, size_t hex_len, size_t *bytes_len) {
    if (hex_len % 2 != 0) {
        return false;
    }

    *bytes_len = hex_len / 2;
    if (*bytes_len == 0 && hex_len == 0) return true;

    for (size_t i = 0; i < *bytes_len; ++i) {
        unsigned int byte_val;
        if (sscanf(hex + 2 * i, "%2x", &byte_val) != 1) {
            return false;
        }
        bytes[i] = (unsigned char) byte_val;
    }
    return true;
}

// 幫助函數：打印字節數組為十六進制字符串
void print_bytes_hex(const unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", bytes[i]);
    }
}

// 幫助函數：將 GMP 大數 (scalar_mpz) 轉換為其在模 N 意義下的 32 字節大端序表示
// Returns true on success, false on error (e.g., internal size mismatch).
bool mpz_to_scalar32(const mpz_t scalar_mpz, const mpz_t n, unsigned char* scalar_bytes) {
    mpz_t temp_scalar;
    mpz_init(temp_scalar);

    // Calculate scalar_mpz mod N, ensuring the result is in [0, N-1]
    mpz_mod(temp_scalar, scalar_mpz, n);
    if (mpz_sgn(temp_scalar) < 0) {
        mpz_add(temp_scalar, temp_scalar, n);
    }

    // Export to 32 bytes, big-endian, zero-padded
    memset(scalar_bytes, 0, 32);

    size_t actual_bytes_exported;
    size_t needed_bytes = mpz_sizeinbase(temp_scalar, 256);

    if (needed_bytes > 32) {
        fprintf(stderr, "內部錯誤: 導出的標量 (%zu 字節) 大於 32 字節 (不應發生)。\n", needed_bytes);
        mpz_clear(temp_scalar);
        return false;
    }

    // mpz_export writes to the beginning in specified order.
    // For 32-byte big-endian, we need the number at the end of the buffer.
    // So we export into the end and zero-pad the beginning.
    mpz_export(scalar_bytes + (32 - needed_bytes), &actual_bytes_exported, 1, 1, 1, 0, temp_scalar);

     // Check if the number of exported bytes matches the needed bytes (it should for size=1 export)
     if (actual_bytes_exported != needed_bytes) {
         // This might indicate an issue with mpz_export behavior or calculation of needed_bytes
         // Print a warning if needed, but don't fail unless needed_bytes > 32
         // fprintf(stderr, "警告: mpz_to_scalar32: 實際導出的字節數 (%zu) 與所需字節數 (%zu) 不符。\n", actual_bytes_exported, needed_bytes);
     }


    mpz_clear(temp_scalar);
    return true;
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "用法: %s <公鑰十六進制>\n", argv[0]);
        fprintf(stderr, "範例: %s 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\n", argv[0]);
        fprintf(stderr, "或: %s 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8\n", argv[0]);
        fprintf(stderr, "注意: 公鑰可以是壓縮 (66 位十六進制) 或非壓縮 (130 位十六進制) 格式。\n");
        return 1;
    }

    const char *pubkey_hex = argv[1];

    // Validate pubkey hex length
    size_t pubkey_hex_len = strlen(pubkey_hex);
    size_t pubkey_bytes_len;

    if (pubkey_hex_len == 66) {
        pubkey_bytes_len = 33; // Compressed format
    } else if (pubkey_hex_len == 130) {
        pubkey_bytes_len = 65; // Uncompressed format
    } else {
        fprintf(stderr, "錯誤: 公鑰長度不正確，應為 66 (壓縮) 或 130 (非壓縮) 個十六進制字符。\n");
        return 1;
    }

    // Buffer large enough for both compressed and uncompressed
    unsigned char pubkey_bytes[65];
    if (!hex_to_bytes(pubkey_hex, pubkey_bytes, pubkey_hex_len, &pubkey_bytes_len)) {
        fprintf(stderr, "錯誤: 無法將公鑰十六進制字符串轉換為字節。\n");
        return 1;
    }

    // Double check the determined length matches the conversion
    if (pubkey_hex_len == 66 && pubkey_bytes_len != 33) {
         fprintf(stderr, "內部錯誤: 壓縮公鑰長度轉換不符 (%zu vs 33)。\n", pubkey_bytes_len);
         return 1;
    }
     if (pubkey_hex_len == 130 && pubkey_bytes_len != 65) {
         fprintf(stderr, "內部錯誤: 非壓縮公鑰長度轉換不符 (%zu vs 65)。\n", pubkey_bytes_len);
         return 1;
    }


    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        fprintf(stderr, "錯誤: 無法創建 secp256k1 上下文。\n");
        return 1;
    }

    secp256k1_pubkey pubkey_Q; // Original Q
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey_Q, pubkey_bytes, pubkey_bytes_len)) {
        fprintf(stderr, "錯誤: 無法解析公鑰。請檢查公鑰格式和值是否有效。\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }

    // --- GMP Variables for Scalars ---
    mpz_t n_mpz, beta_mpz, n_minus_1_mpz, beta_squared_mpz;
    mpz_init(n_mpz);
    mpz_init(beta_mpz);
    mpz_init(n_minus_1_mpz);
    mpz_init(beta_squared_mpz);

    // Set N and beta
    if (mpz_set_str(n_mpz, SECP256K1_N_HEX, 16) == -1) {
        fprintf(stderr, "錯誤: 初始化曲線階 N 失敗。\n");
        goto cleanup_gmp;
    }
     if (mpz_set_str(beta_mpz, SECP256K1_BETA_HEX, 16) == -1) {
        fprintf(stderr, "錯誤: 初始化 Beta 失敗。\n");
        goto cleanup_gmp;
    }

    // Calculate N-1 and beta^2 using GMP
    mpz_sub_ui(n_minus_1_mpz, n_mpz, 1); // N-1
    mpz_mul(beta_squared_mpz, beta_mpz, beta_mpz); // beta * beta
    mpz_mod(beta_squared_mpz, beta_squared_mpz, n_mpz); // (beta*beta) mod N


    // Convert GMP scalars to 32-byte binary format
    unsigned char scalar_n_minus_1[32];
    unsigned char scalar_beta[32];
    unsigned char scalar_beta_squared[32];

    bool scalar_conversion_success = true;
    if (!mpz_to_scalar32(n_minus_1_mpz, n_mpz, scalar_n_minus_1)) scalar_conversion_success = false;
    if (!mpz_to_scalar32(beta_mpz, n_mpz, scalar_beta)) scalar_conversion_success = false;
    if (!mpz_to_scalar32(beta_squared_mpz, n_mpz, scalar_beta_squared)) scalar_conversion_success = false;

    if (!scalar_conversion_success) {
         fprintf(stderr, "錯誤: 轉換 GMP 標量到 32 字節失敗。\n");
         goto cleanup_gmp;
    }


    // --- Calculate the 6 related points using libsecp256k1 tweak_mul ---
    secp256k1_pubkey related_pubkeys[6];
    bool tweak_success = true;

    // Point 1: Q (Original)
    related_pubkeys[0] = pubkey_Q; // Copy

    // Point 2: -Q (Q * (N-1))
    related_pubkeys[1] = pubkey_Q; // Start with Q
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &related_pubkeys[1], scalar_n_minus_1)) {
        fprintf(stderr, "錯誤: 計算 -Q (Q * (N-1)) 失敗。\n");
        tweak_success = false; goto cleanup_context;
    }

    // Point 3: Q * Beta
    related_pubkeys[2] = pubkey_Q; // Start with Q
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &related_pubkeys[2], scalar_beta)) {
        fprintf(stderr, "錯誤: 計算 Q * Beta 失敗。\n");
        tweak_success = false; goto cleanup_context;
    }

    // Point 4: -(Q * Beta) ((Q * Beta) * (N-1))
    related_pubkeys[3] = pubkey_Q; // Start with Q
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &related_pubkeys[3], scalar_beta)) { // Calculate Q * Beta first
         fprintf(stderr, "錯誤: 計算 -(Q * Beta) 的 Q * Beta 部分失敗。\n"); // More specific error
         tweak_success = false; goto cleanup_context;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &related_pubkeys[3], scalar_n_minus_1)) { // Then multiply by N-1
        fprintf(stderr, "錯誤: 計算 -(Q * Beta) 的 *(N-1) 部分失敗。\n");
        tweak_success = false; goto cleanup_context;
    }

    // Point 5: Q * Beta^2
    related_pubkeys[4] = pubkey_Q; // Start with Q
     if (!secp256k1_ec_pubkey_tweak_mul(ctx, &related_pubkeys[4], scalar_beta_squared)) {
        fprintf(stderr, "錯誤: 計算 Q * Beta^2 失敗。\n");
        tweak_success = false; goto cleanup_context;
    }

    // Point 6: -(Q * Beta^2) ((Q * Beta^2) * (N-1))
    related_pubkeys[5] = pubkey_Q; // Start with Q
     if (!secp256k1_ec_pubkey_tweak_mul(ctx, &related_pubkeys[5], scalar_beta_squared)) { // Calculate Q * Beta^2 first
         fprintf(stderr, "錯誤: 計算 -(Q * Beta^2) 的 Q * Beta^2 部分失敗。\n"); // More specific error
         tweak_success = false; goto cleanup_context;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &related_pubkeys[5], scalar_n_minus_1)) { // Then multiply by N-1
        fprintf(stderr, "錯誤: 計算 -(Q * Beta^2) 的 *(N-1) 部分失敗。\n");
        tweak_success = false; goto cleanup_context;
    }

    // --- Output Results ---
    printf("原始輸入公鑰: %s\n", pubkey_hex);
    printf("\n计算的 6 个相关公钥为 (压缩格式)：\n");

    for (int i = 0; i < 6; ++i) {
        unsigned char serialized_pubkey[33]; // Compressed output
        size_t outputlen = sizeof(serialized_pubkey);

        // Serialize the resulting public key in compressed format
        if (secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &outputlen, &related_pubkeys[i], SECP256K1_EC_COMPRESSED)) {
            printf("公钥 %d: ", i + 1);
            print_bytes_hex(serialized_pubkey, outputlen);
            printf("\n");
        } else {
            fprintf(stderr, "錯誤: 無法序列化公鑰 %d。\n", i + 1);
            tweak_success = false; // Mark overall failure if serialization fails
        }
    }


// --- Cleanup ---
cleanup_context:
    secp256k1_context_destroy(ctx);
cleanup_gmp:
    mpz_clear(n_mpz);
    mpz_clear(beta_mpz);
    mpz_clear(n_minus_1_mpz);
    mpz_clear(beta_squared_mpz);

    return tweak_success ? 0 : 1;
}
