// calculator.c
// gcc calculator.c -O3 -lgmp -o c
//作者：8891689
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <gmp.h>

#define MAXLINE 256

// 解析输入字符串 str，自动识别十进制或 "0x"/"0X" 十六进制，结果存入 mpzParse the input string str, automatically identify decimal or "0x"/"0X" hexadecimal, and store the result in mpz
// 返回 0 成功，非 0 失败
int parse_bigint(mpz_t result, const char *str) {
    // 跳过前导空白Returns 0 on success, non-0 on failure
    while (isspace(*str)) str++;

    int base = 10;
    if (str[0]=='0' && (str[1]=='x' || str[1]=='X')) {
        base = 16;
        str += 2;
    }
    // mpz_set_str 返回 0 表示成功mpz_set_str returns 0 if successful.
    if (mpz_set_str(result, str, base) != 0) {
        return -1;
    }
    return 0;
}

// 将 mpz 转为以 "0x" 前缀的十六进制字符串Convert mpz to a hexadecimal string prefixed with "0x"
char* bigint_to_hex(const mpz_t v) {
    // mpz_get_str 第三个参数 base，返回的是不带前缀的字符串The third parameter of mpz_get_str is base, which returns the string without the prefix.
    char *s = mpz_get_str(NULL, 16, v);
    size_t len = strlen(s);
    // 如果是负数，s[0]=='-'If it is a negative number, s[0] == '-'
    int neg = (s[0]=='-');
    const char *digits = neg ? s+1 : s;
    // 分配足够空间：符号 + "0x" + digits + '\0',Allocate enough space: sign + "0x" + digits + '\0'
    size_t out_len = neg + 2 + strlen(digits) + 1;
    char *out = malloc(out_len);
    if (!out) { free(s); return NULL; }
    char *p = out;
    if (neg) *p++ = '-';
    strcpy(p, "0x");
    p += 2;
    strcpy(p, digits);
    free(s);
    return out;
}

int main(void) {
    char line[MAXLINE];
    printf("Large integer calculator大整数进制计算器（C + GMP）\n");
    printf("Supported operators: + - * / ，支持运算符：+  -  *  /\n");
    printf("Type q or Q to quit输入 q 或 Q 退出\n");
    printf("The default is decimal input, please start with 0x or 0X for hexadecimal.默认十进制输入，十六进制请以 0x 或 0X 开头\n\n");

    while (1) {
        printf("Please enter a value请输入数值：");
        if (!fgets(line, sizeof(line), stdin)) {
            break;  // 输入结束
        }
        // 去除尾部换行Remove trailing newline
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0]=='q' || line[0]=='Q') {
            printf("The program exits.程序退出。\n");
            break;
        }
        // 尝试解析为 “<lhs> <op> <rhs>”
        char *p = line;
        // 提取第一个词Extract the first word
        char *tok1 = strtok(p, " \t");
        char *op   = strtok(NULL, " \t");
        char *tok2 = strtok(NULL, " \t");
        
        mpz_t a, b, res;
        mpz_inits(a, b, res, NULL);

        if (tok1 && op && tok2 && strlen(op)==1) {
            // 计算表达式Calculating Expressions
            if (parse_bigint(a, tok1) != 0 || parse_bigint(b, tok2) != 0) {
                printf("Invalid value or incorrect format.无效数值或格式错误。\n\n");
                mpz_clears(a, b, res, NULL);
                continue;
            }
            char oper = op[0];
            int ok = 1;
            switch (oper) {
                case '+': mpz_add(res, a, b); break;
                case '-': mpz_sub(res, a, b); break;
                case '*': mpz_mul(res, a, b); break;
                case '/':
                    if (mpz_sgn(b)==0) {
                        printf("错误：除数不能为 0。\n\n");
                        ok = 0;
                    } else {
                        mpz_tdiv_q(res, a, b);
                    }
                    break;
                default:
                    printf("无效运算符：%c\n\n", oper);
                    ok = 0;
            }
            if (ok) {
                // 输出结果Output
                char *hexstr = bigint_to_hex(res);
                gmp_printf("结果result (10Base进制)：%Zd\n", res);
                printf("结果result (16Base进制)：%s\n\n", hexstr);
                free(hexstr);
            }
        } else {
            // 单一数值，做进制转换Single value, do base conversion
            if (parse_bigint(a, line) != 0) {
                printf("无效数值Invalid value.\n\n");
            } else {
                char *hexstr = bigint_to_hex(a);
                gmp_printf("(10Base进制)：%Zd\n", a);
                printf("(16Base进制)：%s\n\n", hexstr);
                free(hexstr);
            }
        }
        mpz_clears(a, b, res, NULL);
    }
    return 0;
}

