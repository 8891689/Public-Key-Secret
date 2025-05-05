/* random.h — PCG 随机数生成器接口
 * https://github.com/8891689
 */
#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>

/* 用指定种子初始化 RNG */
void rseed(uint64_t seed);

/* 返回一个 32 位无符号随机数 */
uint32_t rndu32(void);

/* 返回一个 (0,1) 区间的 double 随机数 */
double rnd(void);

#endif /* RANDOM_H */

