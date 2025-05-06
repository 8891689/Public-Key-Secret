// 作者：8891689
// gcc key_homomorphism.c -lsecp256k1 -Wall -Wextra -O3 -o kh
//  https://github.com/8891689
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const unsigned char LAMBDA[32] = {
    0x53,0x63,0xad,0x4c,0xc0,0x5c,0x30,0xe0,
    0xa5,0x26,0x1c,0x02,0x88,0x12,0x64,0x5a,
    0x12,0x2e,0x22,0xea,0x20,0x81,0x66,0x78,
    0xdf,0x02,0x96,0x7c,0x1b,0x23,0xbd,0x72
};

static const unsigned char LAMBDA_SQ[32] = {
    0xac,0x9c,0x52,0xb3,0x3f,0xa3,0xcf,0x1f,
    0x5a,0xd9,0xe3,0xfd,0x77,0xed,0x9b,0xa4,
    0xa8,0x80,0xb9,0xfc,0x8e,0xc7,0x39,0xc2,
    0xe0,0xcf,0xc8,0x10,0xb5,0x12,0x83,0xce
};

void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%-18s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int hex2bin(const char* hex, unsigned char* out, size_t len) {
    size_t hex_len = strlen(hex);
    if (hex_len > len * 2) return 0;
    
    // 补零到64字符
    char padded_hex[65] = {0};
    size_t pad_len = len * 2 - hex_len;
    memset(padded_hex, '0', pad_len);
    strcpy(padded_hex + pad_len, hex);
    
    for (size_t i = 0; i < len; i++) {
        if (sscanf(padded_hex + 2*i, "%2hhx", &out[i]) != 1) return 0;
    }
    return 1;
}


int main(int argc, char** argv) {
    if (argc != 2) {
        printf("用法: %s <16进制私钥>\n", argv[0]);
        return 1;
    }

    // 转换16进制私钥
    unsigned char seckey[32];
    if (!hex2bin(argv[1], seckey, 32)) {
        printf("无效的私钥格式\n");
        return 1;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    
    // 验证私钥有效性
    if (!secp256k1_ec_seckey_verify(ctx, seckey)) {
        printf("无效的私钥\n");
        return 1;
    }

    print_hex("\n输入enter私钥", seckey, 32);

    // 生成原始公钥
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)) {
        printf("创建公钥失败\n");
        return 1;
    }

    // 序列化原始公钥
    unsigned char pub_ser[33];
    size_t publen = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub_ser, &publen, &pubkey, SECP256K1_EC_COMPRESSED);
    print_hex("原始original公钥", pub_ser, 33);

    // 生成否定公钥
    secp256k1_pubkey pubkey_neg;
    memcpy(&pubkey_neg, &pubkey, sizeof(pubkey));
    if (!secp256k1_ec_pubkey_negate(ctx, &pubkey_neg)) {
        printf("生成否定公钥失败\n");
        return 1;
    }
    unsigned char pub_neg[33];
    secp256k1_ec_pubkey_serialize(ctx, pub_neg, &publen, &pubkey_neg, SECP256K1_EC_COMPRESSED);

    // 生成 lambda 公钥
    secp256k1_pubkey pubkey_lambda;
    memcpy(&pubkey_lambda, &pubkey, sizeof(pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey_lambda, LAMBDA)) {
        printf("lambda 乘法失败\n");
        return 1;
    }
    unsigned char pub_lambda[33];
    secp256k1_ec_pubkey_serialize(ctx, pub_lambda, &publen, &pubkey_lambda, SECP256K1_EC_COMPRESSED);

    // 生成 lambda 否定公钥
    secp256k1_pubkey pubkey_lambda_neg;
    memcpy(&pubkey_lambda_neg, &pubkey_lambda, sizeof(pubkey_lambda));
    if (!secp256k1_ec_pubkey_negate(ctx, &pubkey_lambda_neg)) {
        printf("生成lambda否定公钥失败\n");
        return 1;
    }
    unsigned char pub_lambda_neg[33];
    secp256k1_ec_pubkey_serialize(ctx, pub_lambda_neg, &publen, &pubkey_lambda_neg, SECP256K1_EC_COMPRESSED);

    // 生成 lambda² 公钥
    secp256k1_pubkey pubkey_lambda_sq;
    memcpy(&pubkey_lambda_sq, &pubkey, sizeof(pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey_lambda_sq, LAMBDA_SQ)) {
        printf("lambda² 乘法失败\n");
        return 1;
    }
    unsigned char pub_lambda_sq[33];
    secp256k1_ec_pubkey_serialize(ctx, pub_lambda_sq, &publen, &pubkey_lambda_sq, SECP256K1_EC_COMPRESSED);

    // 生成 lambda² 否定公钥
    secp256k1_pubkey pubkey_lambda_sq_neg;
    memcpy(&pubkey_lambda_sq_neg, &pubkey_lambda_sq, sizeof(pubkey_lambda_sq));
    if (!secp256k1_ec_pubkey_negate(ctx, &pubkey_lambda_sq_neg)) {
        printf("生成lambda²否定公钥失败\n");
        return 1;
    }
    unsigned char pub_lambda_sq_neg[33];
    secp256k1_ec_pubkey_serialize(ctx, pub_lambda_sq_neg, &publen, &pubkey_lambda_sq_neg, SECP256K1_EC_COMPRESSED);

    // 打印公钥
    print_hex("\n公钥pub1 (Q)", pub_ser, 33);
    print_hex("公钥pub2 (-Q)", pub_neg, 33);
    print_hex("公钥pub3 (φ(Q))", pub_lambda, 33);
    print_hex("公钥pub4 (-φ(Q))", pub_lambda_neg, 33);
    print_hex("公钥pub5 (φ²(Q))", pub_lambda_sq, 33);
    print_hex("公钥pub6 (-φ²(Q))", pub_lambda_sq_neg, 33);

    // 计算私钥
    unsigned char seckeys[6][32];
    memcpy(seckeys[0], seckey, 32);

    // 否定私钥
    memcpy(seckeys[1], seckey, 32);
    if (!secp256k1_ec_seckey_negate(ctx, seckeys[1])) {
        printf("私钥否定失败\n");
        return 1;
    }

    // lambda 私钥
    memcpy(seckeys[2], seckey, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, seckeys[2], LAMBDA)) {
        printf("lambda 私钥计算失败\n");
        return 1;
    }

    // lambda 否定私钥
    memcpy(seckeys[3], seckeys[2], 32);
    if (!secp256k1_ec_seckey_negate(ctx, seckeys[3])) {
        printf("lambda 私钥否定失败\n");
        return 1;
    }

    // lambda² 私钥
    memcpy(seckeys[4], seckey, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, seckeys[4], LAMBDA_SQ)) {
        printf("lambda² 私钥计算失败\n");
        return 1;
    }

    // lambda² 否定私钥
    memcpy(seckeys[5], seckeys[4], 32);
    if (!secp256k1_ec_seckey_negate(ctx, seckeys[5])) {
        printf("lambda² 私钥否定失败\n");
        return 1;
    }

    // 打印私钥
    printf("\n");
    print_hex("私钥key1 (d)", seckeys[0], 32);
    print_hex("私钥key2 (n-d)", seckeys[1], 32);
    print_hex("私钥key3 (lambda*d)", seckeys[2], 32);
    print_hex("私钥key4 (n-lambda*d)", seckeys[3], 32);
    print_hex("私钥key5 (lambda^2*d)", seckeys[4], 32);
    print_hex("私钥key6 (n-lambda^2*d)", seckeys[5], 32);

    secp256k1_context_destroy(ctx);
    return 0;
}
