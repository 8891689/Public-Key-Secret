// 作者：8891689
// pubkey_homomorphism.c
// gcc pubkey_homomorphism.c libsecp256k1.a -lgmp -Wall -Wextra -O3 -o ph
// 计算 secp256k1 公钥的 6 个相关点：Q, -Q, φ(Q), -φ(Q), φ²(Q), -φ²(Q)
// 其中 φ(x,y) = (β·x mod p, y)
// https://github.com/8891689
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <gmp.h>
#include <secp256k1.h>

// secp256k1 素数域 p
const char* SECP256K1_P_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
// 内点同态 β（mod p）
const char* SECP256K1_BETA_HEX = "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee";


// 将十六进制字符串转为字节，bytes_len = hex_len/2
static bool hex_to_bytes(const char *hex, unsigned char *bytes, size_t hex_len, size_t *bytes_len) {
    if (hex_len % 2) return false;
    *bytes_len = hex_len / 2;
    for (size_t i = 0; i < *bytes_len; i++) {
        unsigned int b;
        if (sscanf(hex + 2*i, "%2x", &b) != 1) return false;
        bytes[i] = b;
    }
    return true;
}

// 将 mpz_t（模 p 结果）导出到 32 字节 big-endian
static bool mpz_to_field32(const mpz_t v, const mpz_t p, unsigned char out[32]) {
    mpz_t t; mpz_init(t);
    mpz_mod(t, v, p);
    if (mpz_sgn(t) < 0) mpz_add(t, t, p);
    memset(out, 0, 32);
    if (mpz_sgn(t) == 0) { mpz_clear(t); return true; }
    size_t nbytes = (mpz_sizeinbase(t, 2) + 7) / 8;
    if (nbytes > 32) { mpz_clear(t); return false; }
    size_t got;
    mpz_export(out + (32 - nbytes), &got, 1, 1, 1, 0, t);
    mpz_clear(t);
    return got == nbytes;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "用法: %s <压缩或非压缩公钥 hex>\n", argv[0]);
        return 1;
    }

    // 解析输入公钥
    size_t hex_len = strlen(argv[1]);
    size_t expect = (hex_len == 66 ? 33 : hex_len == 130 ? 65 : 0);
    if (!expect) {
        fprintf(stderr, "错误: 公钥长度应为 66 或 130 字符 hex。\n");
        return 1;
    }
    unsigned char raw[65]; size_t raw_len;
    if (!hex_to_bytes(argv[1], raw, hex_len, &raw_len) || raw_len != expect) {
        fprintf(stderr, "错误: hex 转字节失败。\n");
        return 1;
    }

    // 创建 secp256k1 上下文并解析公钥
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey Q;
    if (!ctx || !secp256k1_ec_pubkey_parse(ctx, &Q, raw, raw_len)) {
        fprintf(stderr, "错误: 无法解析公钥。\n");
        return 1;
    }

    // GMP 变量
    mpz_t p, beta, beta2, xQ, yQ, x1, x2;
    mpz_inits(p, beta, beta2, xQ, yQ, x1, x2, NULL);

    // 载入 p, β
    if (mpz_set_str(p,  SECP256K1_P_HEX, 16) < 0 ||
        mpz_set_str(beta, SECP256K1_BETA_HEX, 16) < 0) {
        fprintf(stderr, "错误: 初始化域参数失败。\n");
        goto cleanup;
    }
    // beta^2 mod p
    mpz_mul(beta2, beta, beta);
    mpz_mod(beta2, beta2, p);

    // 解压原始公钥，取 X/Y
    unsigned char uncompressed[65]; size_t ul = 65;
    if (!secp256k1_ec_pubkey_serialize(ctx, uncompressed, &ul, &Q, SECP256K1_EC_UNCOMPRESSED)) {
        fprintf(stderr, "错误: 无法反序列化公钥。\n");
        goto cleanup;
    }
    mpz_import(xQ, 32, 1, 1, 1, 0, uncompressed + 1);
    mpz_import(yQ, 32, 1, 1, 1, 0, uncompressed + 33);

    // 计算 φ 映射的 X 坐标
    mpz_mul(x1, beta,  xQ); mpz_mod(x1, x1, p);
    mpz_mul(x2, beta2, xQ); mpz_mod(x2, x2, p);

    // 导出为 32 字节
    unsigned char bx1[32], bx2[32];
    if (!mpz_to_field32(x1, p, bx1) || !mpz_to_field32(x2, p, bx2)) {
        fprintf(stderr, "错误: X 坐标导出失败。\n");
        goto cleanup;
    }

    // 准备六个 pubkey 结构
    secp256k1_pubkey R[6];
    // 1. Q
    R[0] = Q;

    // 2. -Q
    R[1] = Q;
    if (!secp256k1_ec_pubkey_negate(ctx, &R[1])) {
        fprintf(stderr, "错误: secp256k1_ec_pubkey_negate(-Q) 失败\n");
        return 1;
    }

    unsigned char tmp[33];

    // 3. phi(Q)
    tmp[0] = mpz_even_p(yQ) ? 0x02 : 0x03;
    memcpy(tmp + 1, bx1, 32);
    if (!secp256k1_ec_pubkey_parse(ctx, &R[2], tmp, 33)) {
        fprintf(stderr, "错误: secp256k1_ec_pubkey_parse(phi(Q)) 失败，请检查 tmp 数值是否正确\n");
        return 1;
    }

    // 4. -phi(Q)
    R[3] = R[2];
    if (!secp256k1_ec_pubkey_negate(ctx, &R[3])) {
        fprintf(stderr, "错误: secp256k1_ec_pubkey_negate(-phi(Q)) 失败\n");
        return 1;
    }

    // 5. phi^2(Q)
    tmp[0] = mpz_even_p(yQ) ? 0x02 : 0x03;
    memcpy(tmp + 1, bx2, 32);
    if (!secp256k1_ec_pubkey_parse(ctx, &R[4], tmp, 33)) {
        fprintf(stderr, "错误: secp256k1_ec_pubkey_parse(phi^2(Q)) 失败，请检查 tmp 数值是否正确\n");
        return 1;
    }

    // 6. -phi^2(Q)
    R[5] = R[4];
    if (!secp256k1_ec_pubkey_negate(ctx, &R[5])) {
        fprintf(stderr, "错误: secp256k1_ec_pubkey_negate(-phi^2(Q)) 失败\n");
        return 1;
    }


    // 输出压缩格式
    const char* lbl[6] = {
        "Q", "-Q", "phi(Q)", "-phi(Q)", "phi^2(Q)", "-phi^2(Q)"
    };
    unsigned char out33[33]; size_t ol = 33;
    printf("输入公钥: %s\n\n", argv[1]);
    for (int i = 0; i < 6; i++) {
        ol = 33;
        secp256k1_ec_pubkey_serialize(ctx, out33, &ol, &R[i], SECP256K1_EC_COMPRESSED);
        printf("%2d. %-10s: ", i+1, lbl[i]);
        for (size_t j = 0; j < ol; j++) printf("%02x", out33[j]);
        printf("\n");
    }

cleanup:
    secp256k1_context_destroy(ctx);
    mpz_clears(p, beta, beta2, xQ, yQ, x1, x2, NULL);
    return 0;
}

