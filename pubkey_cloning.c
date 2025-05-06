/* pubkey_cloning.c
 * gcc pubkey_cloning.c random.c bitrange.c -o p -march=native libsecp256k1.a -lgmp -Wall -Wextra -O3
 *author：8891689 , https://github.com/8891689
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h> // For bool type
#include <unistd.h>  // For getopt, getpid
#include <gmp.h>     // For GMP library
#include <secp256k1.h> // For secp256k1 library
#include <time.h>    // For seeding random number generator
#include <limits.h>  // For ULONG_MAX

#ifdef _WIN32
#include <process.h> // For _getpid on Windows
#define getpid _getpid
#endif

#include "random.h"  
#include "bitrange.h" 

// secp256k1 曲線的階 N
const char* SECP256K1_N_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

// 幫助函數：將十六進制字符串轉換為字節數組
// 成功返回 true，失敗返回 false
bool hex_to_bytes(const char *hex, unsigned char *bytes, size_t hex_len, size_t *bytes_len) {
    if (hex_len % 2 != 0) {
        return false; // Hex string must have an even length
    }

    *bytes_len = hex_len / 2;
    if (*bytes_len == 0 && hex_len == 0) return true; // Handle empty string case

    for (size_t i = 0; i < *bytes_len; ++i) {
        // sscanf("%2hhx") is safe for hex pairs
        if (sscanf(hex + 2 * i, "%2hhx", &bytes[i]) != 1) {
            return false; // Error in scanning a hex pair
        }
    }
    return true;
}

// 幫助函數：打印字節數組為十六進制字符串
void print_bytes_hex(FILE *fp, const unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        fprintf(fp, "%02x", bytes[i]);
    }
}

// 幫助函數：將 GMP 大數 (scalar_mpz) 轉換為其在模 N 意義下的 32 字節大端序表示
// 成功返回 true，失敗返回 false (主要失敗是轉換後的數字異常大)
bool mpz_to_scalar32(mpz_t scalar_mpz, mpz_t n, unsigned char* scalar_bytes) {
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
        fprintf(stderr, "內部錯誤: 導出的標量 (%zu 字節) 大於 32 字節。\n", needed_bytes);
        mpz_clear(temp_scalar);
        return false;
    }

    mpz_export(scalar_bytes + (32 - needed_bytes), &actual_bytes_exported, 1, 1, 1, 0, temp_scalar);

    mpz_clear(temp_scalar);
    return true;
}

// 幫助函數：在指定範圍 [min, max] 內生成一個隨機 GMP 大數
// 返回 true 表示成功， false 表示失敗 (例如，範圍無效或隨機數生成問題)
// 需要事先初始化 mpz_t result, min, max
bool generate_random_scalar_in_range(mpz_t result, mpz_t min, mpz_t max) {
    // Note: min here is already guaranteed to be >= 1 by main's logic

    if (mpz_cmp(min, max) > 0) {
        fprintf(stderr, "錯誤: 無效的隨機數範圍，最小值大於最大值。\n");
        return false;
    }

    mpz_t range_size, rand_full;
    mpz_init(range_size);
    mpz_init(rand_full);

    // Calculate range_size = max - min + 1
    mpz_sub(range_size, max, min);
    mpz_add_ui(range_size, range_size, 1);

    if (mpz_sgn(range_size) <= 0) { // Should handle range_size = 0 or 1 (min==max)
         mpz_set(result, min); // If range_size is 1, result must be min (or max)
         mpz_clear(range_size);
         mpz_clear(rand_full);
         return true;
    }

    // Generate enough random bits to cover the range size plus some extra bits
    size_t range_bits = mpz_sizeinbase(range_size, 2);
    size_t random_bits_needed = range_bits + 64; // Add extra bits to reduce modulo bias
    size_t uint32_count = (random_bits_needed + 31) / 32; // Number of uint32_t needed

    unsigned char* rand_bytes = malloc(uint32_count * sizeof(uint32_t));
    if (!rand_bytes) {
        fprintf(stderr, "錯誤: 分配內存失敗。\n");
        mpz_clear(range_size);
        mpz_clear(rand_full);
        return false;
    }

    // Fill buffer with random uint32s
    for(size_t i = 0; i < uint32_count; ++i) {
        uint32_t r = rndu32();
        rand_bytes[i * 4 + 0] = (r >> 24) & 0xFF;
        rand_bytes[i * 4 + 1] = (r >> 16) & 0xFF;
        rand_bytes[i * 4 + 2] = (r >> 8) & 0xFF;
        rand_bytes[i * 4 + 3] = r & 0xFF;
    }

    // Import random bytes into rand_full (big-endian)
    mpz_import(rand_full, uint32_count * sizeof(uint32_t), 1, 1, 1, 0, rand_bytes);

    free(rand_bytes);

    // Take rand_full modulo range_size
    mpz_mod(result, rand_full, range_size);

    // Add min to shift the result into the correct range [min, max]
    mpz_add(result, result, min);

    // Final sanity check: is result within [min, max]?
    if (mpz_cmp(result, min) < 0 || mpz_cmp(result, max) > 0) {
        fprintf(stderr, "內部錯誤: 生成的隨機數超出指定範圍。\n");
        mpz_clear(range_size);
        mpz_clear(rand_full);
        return false;
    }

    mpz_clear(range_size);
    mpz_clear(rand_full);

    return true;
}


void print_usage(const char *prog_name) {
    fprintf(stderr, "用法: %s <公鑰十六進制> [選項]\n", prog_name);
    fprintf(stderr, "選項:\n");
    fprintf(stderr, "  -n <count>  執行加法和減法操作的次數 (默認 1)。<count> 應是大於 0 的整數。\n");
    fprintf(stderr, "  -v          打印每次操作使用的標量數值並標記原始公鑰。\n");
    fprintf(stderr, "  -R          隨機生成標量 (如果沒有 -b/-r 則範圍為 [1, N-1]，否則為 -b/-r 指定範圍)。\n");
    fprintf(stderr, "  -b <bits>   指定標量範圍 (隨機模式) 或起始標量 (遞增模式)。最低標量為 1。\n");
    fprintf(stderr, "  -r <A:B>    指定標量範圍 (十六進制，隨機模式) 或起始標量 (遞增模式)。最低標量為 1。\n");
    fprintf(stderr, "  -o <file>   將輸出寫入指定文件 (默認輸出到控制台)。\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "必須指定 -R 進入隨機模式，否則進入遞增模式。\n");
    fprintf(stderr, "遞增模式下，必須指定 -b 或 -r 來確定起始標量。\n");
    fprintf(stderr, "隨機模式 (-R) 下，如果指定 -b 或 -r，則使用其範圍；否則使用 [1, N-1]。\n");
    fprintf(stderr, "不能同時指定 -b 和 -r。\n");
    fprintf(stderr, "公鑰可以是壓縮 (66 位十六進制) 或非壓縮 (130 位十六進制) 格式。\n");
    fprintf(stderr, "標量將被處理為模 N。使用的最低標量為 1。\n");
    fprintf(stderr, "示例:\n");
    fprintf(stderr, "  %s 02... -n 10 -R -v         # 隨機模式 [1, N-1], 打印標量\n", prog_name);
    fprintf(stderr, "  %s 02... -n 5 -b 32 -R -o out.txt # 隨機模式 [2^31, 2^32-1], 輸出到文件\n", prog_name);
    fprintf(stderr, "  %s 02... -n 10 -b 32 -v      # 遞增模式, 從 2^31 開始遞增, 打印標量\n", prog_name);
    fprintf(stderr, "  %s 02... -n 5 -r 0:20 -v     # 遞增模式, 從 1 (因為強制最低為1) 開始遞增, 打印標量\n", prog_name);
    fprintf(stderr, "  %s 02... -n 5 -r 1:20        # 遞增模式, 從 1 開始遞增\n", prog_name);
}

int main(int argc, char **argv) {
    // --- 變數聲明與初始化 ---
    const char *pubkey_hex = NULL;
    long long count = 1;
    bool verbose = false;
    bool random_mode = false;
    const char *bitrange_param = NULL;
    const char *range_param = NULL;
    const char *output_filename = NULL;
    FILE *output_fp = stdout; // Default output to console

    bool critical_error = false; // Flag to track if a critical error occurred

    // Declare and Initialize all GMP variables here
    mpz_t min_scalar, max_scalar, n, current_scalar_mpz, neg_current_scalar_mpz;
    mpz_init(min_scalar);
    mpz_init(max_scalar);
    mpz_init(n);
    mpz_init(current_scalar_mpz);
    mpz_init(neg_current_scalar_mpz);

    // Declare and Initialize secp256k1 context pointer to NULL
    secp256k1_context *ctx = NULL;


    // Set curve order N early for range validation
    if (mpz_set_str(n, SECP256K1_N_HEX, 16) == -1) {
        fprintf(stderr, "錯誤: 初始化曲線階 N 失敗。\n");
        critical_error = true;
        goto cleanup; // Jumps to cleanup, all mpz are initialized, ctx is NULL.
    }


    int opt;
    opterr = 0; // Suppress getopt's default error messages
    while ((opt = getopt(argc, argv, "n:vRb:r:o:")) != -1) {
        switch (opt) {
            case 'n':
                count = atoll(optarg);
                if (count <= 0) {
                    fprintf(stderr, "錯誤: 操作次數 -n 必須是大於零的整數。\n");
                    print_usage(argv[0]);
                    critical_error = true;
                    goto cleanup;
                }
                break;
            case 'v':
                verbose = true;
                break;
            case 'R':
                random_mode = true;
                break;
            case 'b':
                bitrange_param = optarg;
                break;
            case 'r':
                range_param = optarg;
                break;
            case 'o':
                output_filename = optarg;
                break;
            case ':': // Missing argument for an option
                fprintf(stderr, "錯誤: 選項 '-%c' 需要一個參數。\n", optopt);
                print_usage(argv[0]);
                critical_error = true;
                goto cleanup;
            case '?': // Unrecognized option
                fprintf(stderr, "錯誤: 未知選項 '-%c'。\n", optopt);
                print_usage(argv[0]);
                critical_error = true;
                goto cleanup;
            default:
                print_usage(argv[0]);
                critical_error = true;
                goto cleanup;
        }
    }

    // Check for mutually exclusive range parameters (-b, -r)
    if (bitrange_param && range_param) {
        fprintf(stderr, "錯誤: 不能同時指定 -b 和 -r。\n");
        print_usage(argv[0]);
        critical_error = true;
        goto cleanup;
    }

    // Determine the scalar range/start based on mode and parameters
    bool range_params_given = bitrange_param || range_param;
    bool range_set_success = false;

    if (random_mode) { // --- Random Mode (-R) ---
        if (range_params_given) {
             // Random within bitrange (-b) or hex range (-r)
             if (bitrange_param) {
                 if (set_bitrange(bitrange_param, min_scalar, max_scalar) == 0) range_set_success = true;
                 else fprintf(stderr, "錯誤: 解析位數範圍參數 '-b %s' 失敗。\n", bitrange_param);
             } else { // must be range_param
                 if (set_range(range_param, min_scalar, max_scalar) == 0) range_set_success = true;
                 else fprintf(stderr, "錯誤: 解析範圍參數 '-r %s' 失敗。\n", range_param);
             }
        } else {
            // Random within full range [1, N-1] if no -b/-r given with -R
            mpz_set_ui(min_scalar, 1);
            mpz_sub_ui(max_scalar, n, 1);
            range_set_success = true; // Full range set successfully
        }
    } else { // --- Incrementing Mode (No -R) ---
        if (range_params_given) {
            // Incrementing from bitrange min (-b) or hex range min (-r)
             if (bitrange_param) {
                 if (set_bitrange(bitrange_param, min_scalar, max_scalar) == 0) range_set_success = true; // Use min_scalar as start
                 else fprintf(stderr, "錯誤: 解析位數範圍參數 '-b %s' 失敗。\n", bitrange_param);
             } else { // must be range_param
                 if (set_range(range_param, min_scalar, max_scalar) == 0) range_set_success = true; // Use min_scalar as start
                 else fprintf(stderr, "錯誤: 解析範圍參數 '-r %s' 失敗。\n", range_param);
             }
        } else {
            // No -R, and no -b/-r - This is an invalid state based on required logic
            fprintf(stderr, "錯誤: 在遞增模式下 (沒有 -R)，必須指定 -b 或 -r 來確定起始標量。\n");
        }
    }

    // Handle range setting failures
    if (!range_set_success) {
        print_usage(argv[0]);
        critical_error = true;
        goto cleanup; // Exit if range setting failed
    }

    // --- Ensure minimum scalar (min_scalar) is at least 1 ---
    // If the parsed minimum is less than 1, force it to 1.
    if (mpz_cmp_ui(min_scalar, 1) < 0) { // Check if min_scalar < 1
         mpz_set_ui(min_scalar, 1);
         // If original range was [0,0] or [-ve, 0], now it's [1,0] or [-ve, 1].
         // This might make max_scalar less than min_scalar. Check for this invalid range below.
    }


    // Final check on the determined range/start (min <= max for random, valid min for incrementing)
    if (mpz_cmp(min_scalar, max_scalar) > 0 && random_mode) {
         // Only an error for random mode where [min, max] range is used for bounds.
         // This catches cases like original range [0,0] which becomes [1,0] after enforcing min=1.
         // It also catches [0, -1] becoming [1, -1] etc.
         fprintf(stderr, "錯誤: 計算出的隨機標量範圍無效 (最小值大於最大值)。這可能由 -b 或 -r 參數引起。\n");
         critical_error = true;
         goto cleanup;
    }

     // It's generally undesirable to use a scalar that is 0 mod N, as s=0 results in P + 0*G = P (original key).
     // With min_scalar now guaranteed to be >= 1, the only way to get 0 mod N is if min_scalar itself is N, 2N, etc.
     // or if the range includes N, 2N etc.
     // Check if the initial scalar (or minimum range value) is 0 mod N.
     // Note: min_scalar is >= 1, so it can't be the integer 0.
     mpz_t temp_min_mod_n;
     mpz_init(temp_min_mod_n);
     mpz_mod(temp_min_mod_n, min_scalar, n);
     if (mpz_sgn(temp_min_mod_n) < 0) mpz_add(temp_min_mod_n, temp_min_mod_n, n); // Ensure [0, N-1] range

     if (mpz_sgn(temp_min_mod_n) == 0) {
          // If min_scalar is >= 1 and min_scalar mod N is 0, it means min_scalar is N, 2N, etc.
          // This is a warning scenario as P + sG where s is a multiple of N is just P.
          fprintf(stderr, "警告: 標量範圍最小值或起始值為 0 mod N。使用此標量會得到原始公鑰。\n");
     }
     mpz_clear(temp_min_mod_n);


    // The remaining non-option arguments should contain the public key hex string
    if (optind >= argc) {
        fprintf(stderr, "錯誤: 必須提供公鑰十六進制字符串。\n");
        print_usage(argv[0]);
        critical_error = true;
        goto cleanup;
    }
    if (optind < argc - 1) {
         fprintf(stderr, "錯誤: 參數過多，公鑰十六進制字符串後不應有其他非選項參數。\n");
         print_usage(argv[0]);
         critical_error = true;
         goto cleanup;
    }
    pubkey_hex = argv[optind];

    // --- 驗證和解析公鑰 ---
    size_t pubkey_hex_len = strlen(pubkey_hex);
    size_t pubkey_bytes_len;
    // Buffer large enough for both compressed and uncompressed
    unsigned char pubkey_bytes[65];

    if (!hex_to_bytes(pubkey_hex, pubkey_bytes, pubkey_hex_len, &pubkey_bytes_len)) {
        fprintf(stderr, "錯誤: 無法將公鑰十六進制字符串轉換為字節，請檢查輸入是否為有效十六進制。\n");
        critical_error = true;
        goto cleanup;
    }

    // Validate public key byte length after conversion
    if (pubkey_bytes_len != 33 && pubkey_bytes_len != 65) {
         fprintf(stderr, "錯誤: 公鑰長度不正確 (%zu 字節)，應為 33 (壓縮) 或 65 (非壓縮) 字節。\n", pubkey_bytes_len);
         critical_error = true;
         goto cleanup;
    }

    // --- 初始化 secp256k1 ---
    // ctx was declared and initialized to NULL at the beginning.
    // Now create the context.
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        fprintf(stderr, "錯誤: 無法創建 secp256k1 上下文。\n");
        critical_error = true;
        goto cleanup; // Go to cleanup. ctx is NULL, so destroy(NULL) is okay.
    }


    secp256k1_pubkey pubkey_orig; // Store original public key
    // secp256k1_ec_pubkey_parse handles both 33-byte and 65-byte inputs
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey_orig, pubkey_bytes, pubkey_bytes_len)) {
        fprintf(stderr, "錯誤: 無法解析公鑰。請檢查公鑰格式和值是否有效。\n");
        critical_error = true;
        goto cleanup; // Go to cleanup if pubkey parsing fails. ctx is valid, will be destroyed.
    }

    // --- 初始化隨機數生成器 (只在隨機模式需要) ---
    if (random_mode) {
        uint64_t seed = (uint64_t)time(NULL);
        seed ^= (uint64_t)getpid() << 32; // POSIX or Windows (_getpid)
        rseed(seed);
    }

    // --- 打開輸出文件 ---
    if (output_filename) {
        output_fp = fopen(output_filename, "w");
        if (!output_fp) {
            fprintf(stderr, "錯誤: 無法打開輸出文件 '%s' 進行寫入。\n", output_filename); // <-- Fixed line
            critical_error = true;
            goto cleanup;
        }
    }

    // --- 主循環：確定標量並執行操作 ---
    unsigned char scalar_bytes[32]; // 32 bytes for the scalar
    unsigned char neg_scalar_bytes[32]; // 32 bytes for the negative scalar

    if (!random_mode) {
        // Initialize starting scalar for incrementing mode before the loop.
        // min_scalar is already guaranteed to be >= 1 here.
        mpz_set(current_scalar_mpz, min_scalar);
    }

    for (long long i = 0; i < count; ++i) {
        // Determine the scalar value (current_scalar_mpz) for this iteration
        if (random_mode) {
             // Random mode: Generate a new random scalar in the determined range [min_scalar, max_scalar]
             // min_scalar is >= 1 here, so the range [min_scalar, max_scalar] will not be [0,0].
             // Generated scalar will be >= 1.
             if (!generate_random_scalar_in_range(current_scalar_mpz, min_scalar, max_scalar)) {
                  fprintf(stderr, "錯誤: 生成隨機標量失敗。\n");
                  critical_error = true;
                  goto cleanup; // Critical error during random generation
             }

             // Convert the generated GMP scalar to the 32-byte format required by libsecp256k1
             // This conversion also implicitly calculates the scalar mod N.
             // Since min_scalar >= 1, the generated scalar will be >= 1.
             // However, it's still possible that a random number >= 1 is a multiple of N. Check and regenerate.
             bool generated_non_zero_scalar_mod_N = false;
             while(!generated_non_zero_scalar_mod_N) {
                 // Convert scalar to bytes for mod N check
                 if (!mpz_to_scalar32(current_scalar_mpz, n, scalar_bytes)) {
                      fprintf(stderr, "錯誤: 轉換隨機標量到字節失敗。\n");
                      critical_error = true;
                      goto cleanup; // Critical error during scalar conversion
                 }
                  bool is_zero_scalar_mod_N = true;
                  for(int j = 0; j < 32; ++j) {
                       if (scalar_bytes[j] != 0) {
                           is_zero_scalar_mod_N = false;
                           break;
                       }
                   }

                 if (is_zero_scalar_mod_N) {
                     fprintf(stderr, "警告: 生成標量為 0 mod N，重新生成。\n");
                     // Need to generate a *new* random scalar within the range.
                     // Re-call the generation function.
                     if (!generate_random_scalar_in_range(current_scalar_mpz, min_scalar, max_scalar)) {
                          fprintf(stderr, "錯誤: 重新生成隨機標量失敗。\n");
                          critical_error = true;
                          goto cleanup;
                     }
                     // Loop continues to check the new scalar
                 } else {
                    // Valid non-zero scalar mod N
                    generated_non_zero_scalar_mod_N = true;
                 }
             } // End while (!generated_non_zero_scalar_mod_N) for random mode


        } else {
             // Incrementing mode: current_scalar_mpz is used.
             // It starts at min_scalar (which is >= 1).
             // Convert to bytes for tweak operation.
             if (!mpz_to_scalar32(current_scalar_mpz, n, scalar_bytes)) {
                  fprintf(stderr, "錯誤: 轉換遞增標量到字節失敗。\n");
                  critical_error = true;
                  goto cleanup; // Critical error during scalar conversion
             }
              // Optional: warn if the converted scalar is 0 mod N in incrementing mode, but NOT for i=0
              bool is_zero_scalar_mod_N = true;
              for(int j = 0; j < 32; ++j) {
                  if (scalar_bytes[j] != 0) {
                      is_zero_scalar_mod_N = false;
                      break;
                  }
              }
              // Only print this warning if it's a later scalar (i > 0) that hits 0 mod N
              if (is_zero_scalar_mod_N && i > 0) {
                   fprintf(stderr, "警告: 遞增標量達到 0 mod N。\n");
                   // We don't regenerate in incrementing mode, just warn.
              }
        }

        // Calculate the negative scalar for subtraction (-current_scalar_mpz)
        mpz_neg(neg_current_scalar_mpz, current_scalar_mpz);

        // Convert negative scalar to 32-byte format mod N
        if (!mpz_to_scalar32(neg_current_scalar_mpz, n, neg_scalar_bytes)) {
              fprintf(stderr, "錯誤: 轉換負標量到字節失敗。\n");
              critical_error = true;
              goto cleanup; // Critical error during scalar conversion
        }


        // --- 執行加法操作 P + sG ---
        secp256k1_pubkey pubkey_plus = pubkey_orig; // Start with the original key copy
        bool tweak_add_success = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey_plus, scalar_bytes);

        // --- 輸出加法結果 ---
        if (tweak_add_success) {
            unsigned char serialized_pubkey_plus[33]; // Compressed output is 33 bytes
            size_t outputlen_plus = sizeof(serialized_pubkey_plus);
             // Always serialize in compressed format
            if (secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey_plus, &outputlen_plus, &pubkey_plus, SECP256K1_EC_COMPRESSED)) {
                print_bytes_hex(output_fp, serialized_pubkey_plus, outputlen_plus);
                if (verbose) {
                     char *scalar_str = mpz_get_str(NULL, 10, current_scalar_mpz); // Print the positive scalar
                     fprintf(output_fp, " = + %s", scalar_str);
                     free(scalar_str);
                }
                fprintf(output_fp, "\n");
            } else {
                 fprintf(stderr, "錯誤: 無法序列化加法結果公鑰。\n");
                 // Not a critical error for the whole program, just this output line.
            }
        } else {
            fprintf(stderr, "錯誤: 加法操作失敗 (結果可能為無窮遠點)。\n");
             if (verbose) {
                  char *scalar_str = mpz_get_str(NULL, 10, current_scalar_mpz);
                  fprintf(output_fp, "加法失敗 = + %s\n", scalar_str); // Indicate failure and scalar
                  free(scalar_str);
             } else {
                  fprintf(output_fp, "加法失敗\n");
             }
        }


        // --- 執行減法操作 P - sG (即 P + (-s)G) ---
        secp256k1_pubkey pubkey_minus = pubkey_orig; // Start with the original key copy again
        bool tweak_minus_success = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey_minus, neg_scalar_bytes); // Add -s

        // --- 輸出減法結果 ---
        if (tweak_minus_success) {
            unsigned char serialized_pubkey_minus[33]; // Compressed output is 33 bytes
            size_t outputlen_minus = sizeof(serialized_pubkey_minus);
             // Always serialize in compressed format
            if (secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey_minus, &outputlen_minus, &pubkey_minus, SECP256K1_EC_COMPRESSED)) {
                print_bytes_hex(output_fp, serialized_pubkey_minus, outputlen_minus);
                 if (verbose) {
                      char *scalar_str = mpz_get_str(NULL, 10, current_scalar_mpz); // Print the original positive scalar
                      fprintf(output_fp, " = - %s", scalar_str);
                      free(scalar_str);
                 }
                fprintf(output_fp, "\n");
            } else {
                fprintf(stderr, "錯誤: 無法序列化減法結果公鑰。\n");
                 // Not a critical error for the whole program.
            }
        } else {
            fprintf(stderr, "錯誤: 減法操作失敗 (結果可能為無窮遠點)。\n");
             if (verbose) {
                  char *scalar_str = mpz_get_str(NULL, 10, current_scalar_mpz);
                  fprintf(output_fp, "減法失敗 = - %s\n", scalar_str); // Indicate failure and scalar
                  free(scalar_str);
             } else {
                  fprintf(output_fp, "減法失敗\n");
             }
        }

        // Flush output file periodically
        if (output_fp != stdout) {
             fflush(output_fp);
        }

        // Increment the scalar for the next iteration if in incrementing mode
        if (!random_mode) {
            mpz_add_ui(current_scalar_mpz, current_scalar_mpz, 1);
             // This scalar value can exceed N, which is handled by mpz_to_scalar32 converting mod N.
        }

    } // End of loop

    // --- 輸出原始公鑰 (目標) ---
    unsigned char serialized_pubkey_orig[33]; // Compressed output is 33 bytes
    size_t outputlen_orig = sizeof(serialized_pubkey_orig);
    // Check if ctx is valid before using it for serialization
    if (ctx != NULL && secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey_orig, &outputlen_orig, &pubkey_orig, SECP256K1_EC_COMPRESSED)) {
        print_bytes_hex(output_fp, serialized_pubkey_orig, outputlen_orig);
        if (verbose) { // Only print "= original" if verbose
             fprintf(output_fp, " = original");
        }
        fprintf(output_fp, "\n"); // Always print a newline
    } else {
        // This error should ideally not happen if context and pubkey_orig were valid earlier,
        // but good to have as a fallback.
        if (ctx == NULL) fprintf(stderr, "內部錯誤: secp256k1 上下文無效，無法序列化原始公鑰。\n");
        else fprintf(stderr, "錯誤: 無法序列化原始公鑰。\n");
        // Still proceed with cleanup
    }


cleanup:
    // --- 清理 ---
    // All GMP variables were initialized early, so clearing is safe.
    mpz_clear(n);
    mpz_clear(min_scalar);
    mpz_clear(max_scalar);
    mpz_clear(current_scalar_mpz);
    mpz_clear(neg_current_scalar_mpz);

    // ctx was initialized to NULL at declaration, so checking and destroying is safe.
    if (ctx != NULL) {
        secp256k1_context_destroy(ctx);
    }

    // Check for file errors on output stream before closing
    if (output_fp != stdout && output_fp != NULL) {
        if (ferror(output_fp)) {
            fprintf(stderr, "錯誤: 寫入輸出文件時發生錯誤。\n");
            critical_error = true; // Indicate file write error as critical
        }
        fclose(output_fp);
    }
    // Check for standard error stream errors too
    if (ferror(stderr)) {
         fprintf(stderr, "錯誤: 寫入標準錯誤時發生錯誤。\n");
         critical_error = true; // Indicate stderr write error as critical
    }

    // Return non-zero if any critical error occurred
    return critical_error ? 1 : 0;
}
