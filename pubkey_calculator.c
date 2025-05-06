// gcc -o pc pubkey_calculator.c -march=native -O3 libsecp256k1.a -lgmp
// author：8891689
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h> // For bool type
#include <gmp.h>     // For GMP library
#include <secp256k1.h> // For secp256k1 library

// secp256k1 曲線的階 N
// N = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
const char* SECP256K1_N_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

// 幫助函數：將十六進制字符串轉換為字節數組
bool hex_to_bytes(const char *hex, unsigned char *bytes, size_t hex_len, size_t *bytes_len) {
    if (hex == NULL || bytes == NULL || bytes_len == NULL) {
        return false; // Basic null check
    }
    if (hex_len % 2 != 0) {
        return false; // Hex string must have even length
    }

    *bytes_len = hex_len / 2;
    if (*bytes_len == 0 && hex_len == 0) return true; // Handle empty string case

    for (size_t i = 0; i < *bytes_len; ++i) {
        // sscanf("%2hhx") is safe for hex pairs
        // It expects a non-null string pointer
        if (sscanf(hex + 2 * i, "%2hhx", &bytes[i]) != 1) {
            return false; // Error in scanning a hex pair (non-hex chars, unexpected end, etc.)
        }
    }
    return true;
}

// 幫助函數：打印字節數組為十六進制字符串
void print_bytes_hex(const unsigned char *bytes, size_t len) {
    if (bytes == NULL) return; // Basic null check
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", bytes[i]);
    }
}

// 幫助函數：將 GMP 大數 (scalar_mpz) 轉換為其在模 N 意義下的 32 字節大端序表示
bool mpz_to_scalar32(mpz_t scalar_mpz, mpz_t n, unsigned char* scalar_bytes) {
    if (scalar_bytes == NULL) return false; // Basic null check

    mpz_t temp_scalar;
    mpz_init(temp_scalar);

    // Calculate scalar_mpz mod N, ensuring the result is in [0, N-1]
    // GMP's mpz_mod result has the same sign as the dividend (scalar_mpz)
    mpz_mod(temp_scalar, scalar_mpz, n);
    // If the result is negative, add N to bring it into the [0, N-1] range
    if (mpz_sgn(temp_scalar) < 0) {
        mpz_add(temp_scalar, temp_scalar, n);
    }

    // Export to 32 bytes, big-endian, zero-padded
    memset(scalar_bytes, 0, 32);

    size_t actual_bytes_exported;
    // mpz_sizeinbase(base 256) gives the number of bytes needed
    size_t needed_bytes = mpz_sizeinbase(temp_scalar, 256);

    if (needed_bytes > 32) {
        // This should theoretically not happen for a number < N,
        // as N is a 256-bit number, fitting in 32 bytes.
        fprintf(stderr, "內部錯誤: 導出的標量 (%zu 字節) 大於 32 字節。\n", needed_bytes);
        mpz_clear(temp_scalar);
        return false;
    }

    // mpz_export writes bytes in the requested order (big-endian here, order=1),
    // starting from the address provided.
    // To get big-endian in a fixed 32-byte buffer, we need to write
    // the number at the end of the buffer, padding the beginning with zeros.
    if (needed_bytes > 0) { // Avoid exporting for a zero value where needed_bytes is 0
       mpz_export(scalar_bytes + (32 - needed_bytes), &actual_bytes_exported, 1, 1, 1, 0, temp_scalar);

       // Check if the number of exported bytes matches the calculated needed bytes.
       // For size=1 export, this should match unless the number is zero (needed_bytes=0, exported=0).
       if (actual_bytes_exported != needed_bytes) {
           // This might indicate an issue, though less critical than > 32 bytes.
           // Let's not fail based on this unless it proves problematic.
           // fprintf(stderr, "警告: 實際導出的字節數 (%zu) 與所需字節數 (%zu) 不符 (非零值)。\n", actual_bytes_exported, needed_bytes); // Debug warning removed
       }
    } else { // needed_bytes is 0, which means temp_scalar is 0.
         actual_bytes_exported = 0; // Manually set as export wasn't called
    }


    mpz_clear(temp_scalar);
    return true;
}


int main(int argc, char **argv) {
    // 預期參數數量：程式名 + 公鑰 + 操作符 + 數值
    if (argc != 4) {
        fprintf(stderr, "用法: %s <公鑰十六進制> <操作符 (+ - x /)> <數值>\n", argv[0]);
        fprintf(stderr, "範例 (十進制): %s 02... + 1\n", argv[0]);
        fprintf(stderr, "範例 (十六進制): %s 02... x 0xFF\n", argv[0]);
        fprintf(stderr, "注意: 公鑰可以是壓縮 (66 位十六進制) 或非壓縮 (130 位十六進制) 格式。\n");
        fprintf(stderr, "注意: 數值可以是任何整數 (包括負數)，支持十進制或 0x/0X 開頭的十六進制。\n");
        fprintf(stderr, "注意: 乘法請使用 'x' 或 'X'。\n"); // 修改這裡
        return 1;
    }

    const char *pubkey_hex = argv[1];
    const char *operator_str = argv[2];
    const char *value_str = argv[3]; // Keep as string initially for GMP

    if (strlen(operator_str) != 1) {
         fprintf(stderr, "錯誤: 操作符必須是單個字符 (+, -, x, X, 或 /)。\n"); // 修改這裡
         return 1;
    }
    char operator_char = operator_str[0];

    // 驗證公鑰長度 (壓縮格式為 66，非壓縮格式為 130)
    size_t pubkey_hex_len = strlen(pubkey_hex);
    size_t expected_pubkey_bytes_len;

    if (pubkey_hex_len == 66) {
        expected_pubkey_bytes_len = 33; // Compressed format
    } else if (pubkey_hex_len == 130) {
        expected_pubkey_bytes_len = 65; // Uncompressed format
    } else {
        fprintf(stderr, "錯誤: 公鑰長度不正確，應為 66 (壓縮) 或 130 (非壓縮) 個十六進制字符。\n");
        return 1;
    }

    // Buffer large enough for both compressed and uncompressed
    unsigned char pubkey_bytes[65];
    size_t actual_pubkey_bytes_len; // hex_to_bytes will set this

    // hex_to_bytes requires the target buffer to be large enough, which pubkey_bytes[65] is.
    if (!hex_to_bytes(pubkey_hex, pubkey_bytes, pubkey_hex_len, &actual_pubkey_bytes_len)) {
        fprintf(stderr, "錯誤: 無法將公鑰十六進制字符串轉換為字節。請檢查是否包含無效字符。\n");
        return 1;
    }

    // Double check the determined length matches the expected length from hex_len
    if (actual_pubkey_bytes_len != expected_pubkey_bytes_len) {
         fprintf(stderr, "內部錯誤: 公鑰字節長度轉換不符 (預期 %zu vs 實際 %zu)。\n", expected_pubkey_bytes_len, actual_pubkey_bytes_len);
         return 1;
    }


    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        fprintf(stderr, "錯誤: 無法創建 secp256k1 上下文。\n");
        return 1;
    }

    secp256k1_pubkey pubkey;
    // secp256k1_ec_pubkey_parse handles both 33-byte and 65-byte inputs correctly
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey_bytes, actual_pubkey_bytes_len)) {
        fprintf(stderr, "錯誤: 無法解析公鑰。請檢查公鑰格式和值是否有效 (例如，點是否在曲線上)。\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }

    // --- GMP 變量初始化 ---
    mpz_t n, value_mpz, tweak_scalar_mpz;
    mpz_init(n);
    mpz_init(value_mpz);
    mpz_init(tweak_scalar_mpz); // This will hold the scalar value *before* mod N and byte conversion

    // 設置曲線階 N
    if (mpz_set_str(n, SECP256K1_N_HEX, 16) == -1) {
        fprintf(stderr, "錯誤: 初始化曲線階 N 失敗。\n");
        mpz_clear(n);
        mpz_clear(value_mpz);
        mpz_clear(tweak_scalar_mpz);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    // --- 將輸入的數值字符串轉換為 GMP 大數，支持十進制或十六進制 (手動處理 0x 前綴) ---
    int input_base = 10; // Default to decimal
    const char *parse_str = value_str; // Pointer to the string part to parse

    // Check for hexadecimal prefix "0x" or "0X" and ensure there are characters after the prefix
    if (strlen(value_str) >= 2 &&
        ((value_str[0] == '0' && (value_str[1] == 'x' || value_str[1] == 'X')))) {
        input_base = 16;
        parse_str = value_str + 2; // Skip "0x" or "0X"
         // Check if the string is just "0x" or "0X". If so, parse_str will point to the null terminator.
         // mpz_set_str("", 16) should correctly parse as 0. So this is okay.
    }

    if (mpz_set_str(value_mpz, parse_str, input_base) == -1) {
         fprintf(stderr, "錯誤: 無法將數值 '%s' 轉換為數字 (請檢查是否包含無效字符或格式)。\n", value_str);
         mpz_clear(n);
         mpz_clear(value_mpz);
         mpz_clear(tweak_scalar_mpz);
         secp256k1_context_destroy(ctx);
         return 1;
    }
    // --- 數值轉換結束 ---


    bool scalar_calc_success = false;
    unsigned char scalar_bytes[32]; // 32 bytes for the scalar
    char operation_name[20];
    bool use_tweak_add = false; // Flag to determine which tweak function to use

    // --- 根據操作符計算用於 tweak 函數的 GMP 標量 (tweak_scalar_mpz) ---
    if (operator_char == '+') {
        // 加法：使用的標量是 value
        mpz_set(tweak_scalar_mpz, value_mpz);
        scalar_calc_success = true;
        use_tweak_add = true;
        strcpy(operation_name, "加法");

    } else if (operator_char == '-') {
        // 減法：使用的標量是 -value
        mpz_neg(tweak_scalar_mpz, value_mpz);
        scalar_calc_success = true;
        use_tweak_add = true;
        strcpy(operation_name, "減法");

    } else if (operator_char == 'x' || operator_char == 'X') { // 修改這裡
        // 乘法：使用的標量是 value
        mpz_set(tweak_scalar_mpz, value_mpz);
        scalar_calc_success = true;
        use_tweak_add = false; // Use tweak_mul
        strcpy(operation_name, "乘法");

    } else if (operator_char == '/') {
        // 除法：使用的標量是 value 的模逆元 mod N
        mpz_t value_mod_n;
        mpz_init(value_mod_n);
        // Calculate value mod N. Need result in [1, N-1] for inverse.
        mpz_mod(value_mod_n, value_mpz, n);
         // Ensure value_mod_n is positive and non-zero in [1, N-1] for inversion
         if (mpz_sgn(value_mod_n) <= 0) { // Check for 0 or negative results from mpz_mod
             if (mpz_sgn(value_mod_n) == 0) {
                 fprintf(stderr, "錯誤: 除數不能為 0 或 N 的倍數。\n");
             } else { // Should technically not happen if value_mod_n < 0 after mpz_mod, but good to be safe
                 mpz_add(value_mod_n, value_mod_n, n);
                 if (mpz_sgn(value_mod_n) == 0) { // Check again after adding N
                     fprintf(stderr, "錯誤: 除數不能為 0 或 N 的倍數。\n");
                 } else {
                    // Now value_mod_n is in [1, N-1], proceed to invert
                    if (mpz_invert(tweak_scalar_mpz, value_mod_n, n)) {
                        scalar_calc_success = true;
                        use_tweak_add = false; // Use tweak_mul
                    } else {
                        // This case should ideally only happen if value_mod_n is not coprime to N,
                        // but N is prime, so this means value_mod_n is a multiple of N, which
                        // was handled by the mpz_sgn check above.
                        fprintf(stderr, "內部錯誤: 計算數值 '%s' 模 N 的模逆元失敗。\n", value_str);
                        scalar_calc_success = false;
                    }
                 }
             }
         } else { // value_mod_n is already > 0 (and < N because it's mod N)
              if (mpz_invert(tweak_scalar_mpz, value_mod_n, n)) {
                 scalar_calc_success = true;
                 use_tweak_add = false; // Use tweak_mul
             } else {
                 fprintf(stderr, "內部錯誤: 計算數值 '%s' 模 N 的模逆元失敗 (值 > 0)。\n", value_str);
                 scalar_calc_success = false;
             }
         }

        mpz_clear(value_mod_n);
        strcpy(operation_name, "除法");

    } else {
        fprintf(stderr, "錯誤: 不支持的操作符 '%c'。\n", operator_char);
        // scalar_calc_success remains false
    }

    bool tweak_success = false;

    // --- 將計算出的 GMP 標量轉換為 32 字節，並執行 tweak 操作 ---
    if (scalar_calc_success) {
        // Convert the calculated GMP scalar (tweak_scalar_mpz) to the 32-byte format required by libsecp256k1
        if (mpz_to_scalar32(tweak_scalar_mpz, n, scalar_bytes)) {

            // Call the appropriate tweak function
            if (use_tweak_add) {
                 // secp256k1_ec_pubkey_tweak_add returns 1 on success, 0 if the result is the point at infinity.
                 tweak_success = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, scalar_bytes);
            } else { // use_tweak_mul
                 // secp256k1_ec_pubkey_tweak_mul returns 1 on success, 0 if the scalar is 0 or N (which results in point at infinity).
                 tweak_success = secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, scalar_bytes);
            }

        } else {
            // Error message printed inside mpz_to_scalar32
            tweak_success = false; // Ensure tweak_success is false on conversion error
        }
    } else {
         // scalar_calc_success was false, error message already printed
         tweak_success = false; // Ensure tweak_success is false if scalar calculation failed
    }


    // --- 輸出結果 (默認輸出壓縮格式) ---
    // Check if the tweak operation itself returned success (1) which means the result is not the point at infinity
    if (tweak_success) {
        unsigned char serialized_pubkey[33]; // Compressed output is 33 bytes
        size_t outputlen = sizeof(serialized_pubkey);

        // Serialize the resulting public key in compressed format
        // secp256k1_ec_pubkey_serialize returns 1 on success, 0 on failure (e.g., pubkey is point at infinity).
        // However, since tweak_success is 1, the pubkey should not be the point at infinity here.
        if (secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &outputlen, &pubkey, SECP256K1_EC_COMPRESSED)) {
            printf("%s 結果(result): ", operation_name); // Specify compressed output
            print_bytes_hex(serialized_pubkey, outputlen);
            printf("\n");
        } else {
            // This failure case should ideally not happen if tweak_success was true,
            // unless there's an internal issue with serialization after a successful tweak.
            fprintf(stderr, "錯誤: 無法序列化結果公鑰。\n");
            return 1; // Exit with error code
        }
    } else {
        // tweak_success was 0 (for point at infinity from tweak_add/mul) or false due to earlier error (conversion, inverse, etc.)
        // Print a generic failure message, specific errors might have been printed already
        // Distinguish between calculation/conversion errors and the point at infinity result
        bool is_calc_error = !scalar_calc_success; // Did the scalar calculation itself fail?
        bool is_tweak_api_failure = scalar_calc_success && !tweak_success; // Did the API call return 0 after successful scalar calc/conv?

        if (is_calc_error) {
             // Specific error messages already printed by mpz_set_str, mpz_invert, etc.
             fprintf(stderr, "%s 操作失敗 (計算或轉換錯誤)。\n", operation_name);
        } else if (is_tweak_api_failure) {
             // The secp256k1 API returned 0, indicating point at infinity.
             fprintf(stderr, "%s 操作結果為無窮遠點。\n", operation_name);
        } else {
             // Should not reach here if logic is sound, but as a fallback
             fprintf(stderr, "%s 操作失敗 (未知錯誤)。\n", operation_name);
        }

        return 1; // Exit with error code
    }

    // --- 清理 ---
    mpz_clear(n);
    mpz_clear(value_mpz);
    mpz_clear(tweak_scalar_mpz);
    secp256k1_context_destroy(ctx);

    return 0; // Success
}
