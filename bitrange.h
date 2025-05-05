/* bitrange.h
 */
#ifndef BITRANGE_H
#define BITRANGE_H

#include <gmp.h>

/**
 * 按位数设置范围：
 *   bits ∈ [1,256]
 *   min_out = 2^(bits-1)
 *   max_out = 2^bits - 1
 *
 * @return 0 成功，-1 失败（参数非法）
 */
int set_bitrange(const char *param, mpz_t min_out, mpz_t max_out);

/**
 * 按 A:B 设置范围（16 进制）：
 *   param 格式 "A:B"（都为十六进制字符串）
 *   min_out = A
 *   max_out = B
 *
 * @return 0 成功，-1 失败（格式/解析错误）
 */
int set_range(const char *param, mpz_t min_out, mpz_t max_out);

#endif /* BITRANGE_H */

