// 作者：8891689
//  gcc key_homomorphism.c -o key libsecp256k1.a -lgmp

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
// 處理的 hex 字符串長度必須是偶數
bool hex_to_bytes(const char *hex, unsigned char *bytes, size_t hex_len, size_t *bytes_len) {
    if (hex_len % 2 != 0) {
        // 如果輸入的 hex_len 是奇數，這是無效的十六進制字符串
        fprintf(stderr, "錯誤: 十六進制字符串長度必須是偶數。\n");
        return false;
    }

    *bytes_len = hex_len / 2;
    if (*bytes_len == 0 && hex_len == 0) return true;

    for (size_t i = 0; i < *bytes_len; ++i) {
        unsigned int byte_val;
        // 注意：sscanf 的 %2x 要求正好讀取兩個十六進制字符。
        if (sscanf(hex + 2 * i, "%2x", &byte_val) != 1) {
             // 如果讀取失敗，可能是非十六進制字符
             fprintf(stderr, "錯誤: 十六進制字符串包含無效字符。\n");
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
// 返回 true 表示成功，false 表示失敗 (例如，導出的字節超過 32 字節)。
// 標量會先取模 N 以確保結果在 [0, N-1] 範圍內。
// 這是用於生成私鑰的標準 32 字節格式。
bool mpz_to_scalar32(const mpz_t scalar_mpz, const mpz_t n, unsigned char* scalar_bytes) {
    mpz_t temp_scalar;
    mpz_init(temp_scalar);

    // 將 scalar_mpz 取模 N，確保結果在 [0, N-1] 範圍內
    mpz_mod(temp_scalar, scalar_mpz, n);
    if (mpz_sgn(temp_scalar) < 0) { // 確保負數取模後為正數 (GMP 慣例)
        mpz_add(temp_scalar, temp_scalar, n);
    }

    // 確定表示 temp_scalar 需要的字節數 (使用 mpz_sizeinbase 256)
    size_t needed_bytes = mpz_sizeinbase(temp_scalar, 256);

    if (needed_bytes > 32) {
        // 如果取模 N 後的結果大於 32 字節，說明出錯了 (N 本身就適合 32 字節)
        fprintf(stderr, "內部錯誤: mpz_to_scalar32: 導出的標量 (%zu 字節) 大於 32 字節。\n", needed_bytes);
        mpz_clear(temp_scalar);
        return false;
    }

    // 清零 32 字節緩衝區，用於前面填充零
    memset(scalar_bytes, 0, 32);

    size_t actual_bytes_exported;
    if (needed_bytes > 0) {
         // 將數字導出到 32 字節緩衝區的末尾，實現大端序填充。
         mpz_export(scalar_bytes + (32 - needed_bytes), &actual_bytes_exported, 1, 1, 1, 0, temp_scalar);
         if (actual_bytes_exported != needed_bytes) {
              // This case should not happen if needed_bytes > 0.
              fprintf(stderr, "警告: mpz_to_scalar32: 實際導出的字節數 (%zu) 與所需字節數 (%zu) 不符 (當 needed_bytes > 0)。\n", actual_bytes_exported, needed_bytes);
         }
    }
    // 如果 needed_bytes 是 0 (標量為 0)，mpz_export 不會寫入任何字節，
    // scalar_bytes 會保持全零，這是正確的 32 字節表示。

    mpz_clear(temp_scalar);
    return true;
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "用法: %s <私鑰十六進制>\n", argv[0]);
        fprintf(stderr, "範例: %s 0000000000000000000000000000000000000000000000000000000000000001\n", argv[0]);
         fprintf(stderr, "範例 (短輸入): %s 1\n", argv[0]); // 添加短輸入範例
        fprintf(stderr, "注意: 私鑰應為最多 64 位十六進制字符，不足時自動填充前導零。\n");
        return 1;
    }

    const char *privkey_hex_input = argv[1];
    size_t privkey_hex_len = strlen(privkey_hex_input);

    // 檢查輸入長度，不允許超過 64
    if (privkey_hex_len > 64) {
        fprintf(stderr, "錯誤: 私鑰長度過長，應為最多 64 個十六進制字符。\n");
        return 1;
    }
     // 檢查長度是否為空 (雖 strlen >= 0 但穩妥)
    if (privkey_hex_len == 0) {
         fprintf(stderr, "錯誤: 私鑰輸入不能為空字符串。\n");
         return 1;
    }


    // --- 自動填充前導零 ---
    char padded_privkey_hex[65]; // 64 chars + null terminator
    memset(padded_privkey_hex, '0', 64); // 用 '0' 填充整個緩衝區
    padded_privkey_hex[64] = '\0'; // 確保字符串以 null 結尾

    // 將原始輸入拷貝到緩衝區的末尾
    size_t padding_len = 64 - privkey_hex_len;
    memcpy(padded_privkey_hex + padding_len, privkey_hex_input, privkey_hex_len);


    // 將填充後的十六進制字符串轉換為 32 字節的二進制數據
    unsigned char privkey_bytes[32];
    size_t privkey_bytes_len_check; // 用于接收 hex_to_bytes 转换出的字节数

    // 现在调用 hex_to_bytes 时，我们传入固定长度 64
    if (!hex_to_bytes(padded_privkey_hex, privkey_bytes, 64, &privkey_bytes_len_check)) {
        // hex_to_bytes 内部会检查长度是否偶数 (64 是偶数)，并检查是否包含非十六进制字符
        // 如果转换失败，错误信息已经在 hex_to_bytes 中打印
        return 1;
    }

    // 双重检查转换出的字节数是否是 32
    if (privkey_bytes_len_check != 32) {
         fprintf(stderr, "內部錯誤: 填充後的私鑰長度轉換不符 (%zu vs 32)。\n", privkey_bytes_len_check);
         return 1;
    }


    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        fprintf(stderr, "錯誤: 無法創建 secp256k1 上下文。\n");
        return 1;
    }

    // --- GMP 變量 ---
    mpz_t n_mpz, beta_mpz, n_minus_1_mpz, beta_squared_mpz, original_privkey_mpz;
    mpz_t privkey_mpz_list[6]; // 存放 6 個私鑰的 GMP 數字

    mpz_init(n_mpz);
    mpz_init(beta_mpz);
    mpz_init(n_minus_1_mpz);
    mpz_init(beta_squared_mpz);
    mpz_init(original_privkey_mpz);

     // 初始化存放 6 個私鑰的 GMP 變量
    for(int i = 0; i < 6; ++i) {
        mpz_init(privkey_mpz_list[i]);
    }

    // 使用 GMP 設置 N 和 beta
    if (mpz_set_str(n_mpz, SECP256K1_N_HEX, 16) == -1) {
        fprintf(stderr, "錯誤: 初始化曲線階 N 失敗。\n");
        goto cleanup_gmp;
    }
     if (mpz_set_str(beta_mpz, SECP256K1_BETA_HEX, 16) == -1) {
        fprintf(stderr, "錯誤: 初始化 Beta 失敗。\n");
        goto cleanup_gmp;
    }

    // 使用 GMP 計算 N-1 和 beta^2
    mpz_sub_ui(n_minus_1_mpz, n_mpz, 1); // N-1
    mpz_mul(beta_squared_mpz, beta_mpz, beta_mpz); // beta * beta
    mpz_mod(beta_squared_mpz, beta_squared_mpz, n_mpz); // (beta*beta) mod N

    // 將 **32字節** 的私鑰字節數據轉換為 GMP 數字
    // 因為 privkey_bytes 已经是 32 字节标准格式 (大端序，填充零)，直接导入即可
    mpz_import(original_privkey_mpz, 32, 1, 1, 1, 0, privkey_bytes);

    // 檢查原始私鑰是否有效 (非零且小於 N)
    // 私鑰 0 在數學上無效。私鑰 >= N 也是無效的。
    if (mpz_sgn(original_privkey_mpz) == 0 || mpz_cmp(original_privkey_mpz, n_mpz) >= 0) {
         // GMP import 32 bytes should always result in a value < 2^256.
         // N is slightly less than 2^256. The only way this check for >= N should fail
         // for a valid 32-byte input is if the input was one of the few values between N and 2^256.
         // But the 0 check is important.
         fprintf(stderr, "錯誤: 輸入私鑰值無效 (為零或大於等於曲線階 N)。\n");
         goto cleanup_gmp;
    }


    // --- 計算 6 個相關的私鑰 (GMP 數字) ---
    // k_1 = k (原始私鑰)
    mpz_set(privkey_mpz_list[0], original_privkey_mpz);

    // k_2 = -k mod N = (N - k) mod N
    // 因為 1 <= k <= N-1，所以 N-k 的結果在 [1, N-1] 範圍內，已經是正確的模 N 結果。
    mpz_sub(privkey_mpz_list[1], n_mpz, original_privkey_mpz);

    // k_3 = k * Beta mod N
    mpz_mul(privkey_mpz_list[2], original_privkey_mpz, beta_mpz);
    mpz_mod(privkey_mpz_list[2], privkey_mpz_list[2], n_mpz);

    // k_4 = k * Beta * (N-1) mod N = k_3 * (N-1) mod N
    mpz_mul(privkey_mpz_list[3], privkey_mpz_list[2], n_minus_1_mpz);
    mpz_mod(privkey_mpz_list[3], privkey_mpz_list[3], n_mpz);

    // k_5 = k * Beta^2 mod N
    mpz_mul(privkey_mpz_list[4], original_privkey_mpz, beta_squared_mpz);
    mpz_mod(privkey_mpz_list[4], privkey_mpz_list[4], n_mpz);

    // k_6 = k * Beta^2 * (N-1) mod N = k_5 * (N-1) mod N
    mpz_mul(privkey_mpz_list[5], privkey_mpz_list[4], n_minus_1_mpz);
    mpz_mod(privkey_mpz_list[5], privkey_mpz_list[5], n_mpz);


    // --- 輸出結果：每對 (私鑰, 對應公鑰) ---
    // 打印填充零後的私鑰，作為實際處理的值
    printf("處理的私鑰 (填充零後): %s\n", padded_privkey_hex);
    printf("\n計算出的 6 對私鑰和對應公鑰 (基於 Endomorphism 特性):\n");

    const char* pair_descriptions[6] = {
        "1. 原始私鑰 (還原處)",
        "2. 否定私鑰 (-k mod N)",
        "3. 乘以 Beta 的私鑰 (k * Beta mod N)",
        "4. 乘以 Beta 的否定私鑰 (-k * Beta mod N)",
        "5. 乘以 Beta^2 的私鑰 (k * Beta^2 mod N)",
        "6. 乘以 Beta^2 的否定私鑰 (-k * Beta^2 mod N)"
    };

    bool overall_success = true; // 追蹤是否有任何關鍵錯誤發生

    for (int i = 0; i < 6; ++i) {
        printf("\n%s:\n", pair_descriptions[i]);

        // 将当前的私鑰 GMP 数字转换为 secp256k1 所需的 32 字节二进格式 (大端序)
        unsigned char current_privkey_bytes[32];
        // mpz_to_scalar32 确保结果在 [0, N-1] 范围内且为 32 字节，并填充前导零
        if (!mpz_to_scalar32(privkey_mpz_list[i], n_mpz, current_privkey_bytes)) {
             fprintf(stderr, "  錯誤: 無法將計算出的私鑰轉換為 32 字節二進制。\n");
             overall_success = false;
             continue; // 處理下一個私鑰對
        }

        // 打印 32 字節的私鑰二進制數據為 64 個十六進制字符。
        // print_bytes_hex 函数会确保每个字节都打印为两个字符（例如，0 会打印为 "00"），
        // 因此 32 个字节总是打印为 64 个十六进制字符，包括前导零。
        printf("  私鑰 (Hex): ");
        print_bytes_hex(current_privkey_bytes, 32); // Always print 32 bytes as 64 hex chars
        printf("\n");


        // 使用 secp256k1_ec_pubkey_create 導出對應的公鑰
        secp256k1_pubkey current_pubkey;

        // secp256k1_ec_pubkey_create 對於無效的私鑰 (零或 >= N) 返回 0
        // 我們的 mpz_to_scalar32 確保了私鑰在 [0, N-1] 範圍內且是 32 字節。
        // 因此，創建公鑰失敗的唯一合法情況是私鑰值恰好為 0 (0x0...0)。
        // 檢查 32 字節緩衝區是否全零
        bool is_zero_privkey_bytes = true;
        for(int j=0; j<32; ++j) { if(current_privkey_bytes[j] != 0) { is_zero_privkey_bytes = false; break; } }

        if (!is_zero_privkey_bytes && secp256k1_ec_pubkey_create(ctx, &current_pubkey, current_privkey_bytes)) {
             // 公鑰創建成功，序列化並打印公鑰。
             bool serialize_success = true;

             // 序列化並打印公鑰 (壓縮格式)
             unsigned char serialized_pubkey_comp[33];
             size_t comp_len = sizeof(serialized_pubkey_comp);
             if (secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey_comp, &comp_len, &current_pubkey, SECP256K1_EC_COMPRESSED)) {
                 printf("  對應公鑰 (壓縮格式): ");
                 print_bytes_hex(serialized_pubkey_comp, comp_len);
                 printf("\n");
             } else {
                 fprintf(stderr, "  警告: 無法序列化計算出的公鑰 %d (壓縮格式)。\n", i + 1);
                 serialize_success = false;
             }

             // 序列化並打印公鑰 (非壓縮格式)
             unsigned char serialized_pubkey_uncomp[65];
             size_t uncomp_len = sizeof(serialized_pubkey_uncomp);
             if (secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey_uncomp, &uncomp_len, &current_pubkey, SECP256K1_EC_UNCOMPRESSED)) {
                  printf("  對應公鑰 (非壓縮格式): ");
                  print_bytes_hex(serialized_pubkey_uncomp, uncomp_len);
                  printf("\n");
              } else {
                  fprintf(stderr, "  警告: 無法序列化計算出的公鑰 %d (非壓縮格式)。\n", i + 1);
                  serialize_success = false;
              }

              if (!serialize_success) overall_success = false; // 序列化失敗視為部分失敗

        } else {
             // secp256k1_ec_pubkey_create 失敗。
             // If private key byte representation is zero, print a specific message.
             if (is_zero_privkey_bytes) {
                  fprintf(stderr, "  警告: 計算出的私鑰為零，無法生成對應公鑰 (私鑰 0x0...0 無效)。\n");
                  // Note: This check should be redundant if the original input private key was not 0,
                  // as the scalar multiplications mod N should not result in 0 for the secp256k1 curve
                  // unless the original scalar itself was a multiple of N (which is invalid) or 0.
                  // But keeping the check is safer.
             } else {
                 // This case should theoretically not happen if mpz_to_scalar32 is correct and scalar is not 0.
                 // It might indicate a scalar >= N (caught by mpz_to_scalar32 but perhaps the check failed)
                 // or an internal libsecp256k1 issue, though unlikely with valid inputs.
                 fprintf(stderr, "  錯誤: 無法根據計算出的私鑰生成公鑰 (私鑰可能無效，雖已轉換為 32 字節)。\n");
                 overall_success = false;
             }
        }
    }


// --- 清理 ---
cleanup_gmp:
    mpz_clear(n_mpz);
    mpz_clear(beta_mpz);
    mpz_clear(n_minus_1_mpz);
    mpz_clear(beta_squared_mpz);
    mpz_clear(original_privkey_mpz);

    for(int i = 0; i < 6; ++i) {
        mpz_clear(privkey_mpz_list[i]);
    }

cleanup_context:
    secp256k1_context_destroy(ctx);

    // 如果所有主要步驟都成功，返回 0
    return overall_success ? 0 : 1;
}
