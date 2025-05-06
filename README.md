# Preface
I have been researching public keys for a long time. I uploaded the tools I used before for everyone to use. I personally think they are helpful for solving puzzles. For example, the public key cloner can clone the public keys of 135 questions countless times, which improves the hit rate. It also adds a number at the back. Assuming you hit it, you can use the public key calculator to get the original private key! A calculator is also uploaded, which can convert decimal and hexadecimal freely and calculate, which is useful for making cloned public keys. For the other 5 programs, one is interior point homomorphic calculation. For example, other programs calculate another private key, which can directly return the subject public key, or the subject public key corresponding to the public key, because they have 2 function structures. Generally speaking, the interior homomorphism in the directory is used, and the one in the file package is another. There is also a software that will not be announced to the outside world for the time being, because it is a weakness of the public key. It is extremely easy to succeed in 135 puzzles. Of course, it also requires strong mathematical support. Okay, let me introduce how to use and compile and run them.

## Building

The program depends on the "libsecp256k1" library and the multiple-precision arithmetic library -lgmp. I have packaged secp256k1 as a static library and can be linked directly. Generally, the system has a multi-precision arithmetic library. If it is not available, you need to install it:
1. Debian / Ubuntu (using apt):

```bash
sudo apt update && sudo apt install libgmp-dev libsecp256k1-dev
ro
sudo apt-get update
sudo apt-get install libsecp256k1-dev
```
2. macOS

If Homebrew is not installed:
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```
Install GMP
```
brew install gmp
```
Install secp256k1
```
brew install secp256k1
```
Can be combined and installed:
```
brew install gmp secp256k1
```
3. Windows

Install MSYS2 and start the corresponding MinGW terminal
Use pacman to install the math library (taking 64-bit as an example)
```
pacman -S mingw-w64-x86_64-gmp
pacman -S mingw-w64-x86_64-secp256k1
```
Can be combined and installed:
```
pacman -S mingw-w64-x86_64-gmp mingw-w64-x86_64-secp256k1
```

# Compile the code using gcc:

libsecp256k1.a static library, and gmp are downloaded, just compile it directly.

One-click compilation
```
make
```
One-click cleaning
```
make clean
```
# After successful compilation, you will get executable files named kh, c, p, pc, ph.

For example, single or multiple usage
```
gcc key_homomorphism.c libsecp256k1.a -Wall -Wextra -O3 -o kh
gcc calculator.c -lgmp -O3 -o c
gcc pubkey_calculator.c -march=native libsecp256k1.a -lgmp -O3 -o pc
gcc pubkey_cloning.c random.c bitrange.c -march=native libsecp256k1.a -lgmp -Wall -Wextra -O3 -o p
gcc pubkey_homomorphism.c libsecp256k1.a -lgmp -Wall -Wextra -O3 -o ph

```

Parameter Description:

First, let me introduce the pubkey_cloning.c,p program, which is a public key cloner. -n <count> The number of addition and subtraction operations to perform (default 1). It should be an integer greater than 0.
```
-n     The number of cloned public keys, for example 100, is -n 100, depending on your needs, you can customize it.

-v     Print the scalar value used for each operation (actually the cloned encoding, used to recover the principal private key.) and mark the original public key.

-R     Randomly generate scalars and encode. (If there is no -b/-r, the range is [1, N-1], otherwise -b/-r specifies the range.

-b     <bits> specifies the scalar range, the number of puzzles that can be made using the public key, for example, 135 puzzles. If you don't want to run a jigsaw puzzle, then BTC is 256 bits, so fill in 256. (Random mode) or starting scalar (Incremental mode). The lowest scalar is 1.

-r     <A:B> specifies the scalar range, and can also specify the range, (Hexadecimal, random mode) or starting scalar (Incremental mode). The lowest scalar is 1.

-o     <file> writes the output to the specified file, and the file name needs to be filled in. (Default output to the console).

```

Examples:

```
./p 02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16 -b 135 -n 100 -R -v -o Public_key_cloning.txt

./p 02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16 -b 135 -n 100 -R -v -o Public_key_cloning.txt
[+] bits=135 → min=2^(135-1)=4000000000000000000000000000000000, max=2^135-1=7fffffffffffffffffffffffffffffffff

```
For example, in a puzzle game- B 135 is used as an example of filling the public key- Generate 100 cloned public keys for n 100- R is a random pattern- The 'v' command places a specific numeric number after each public key clone, and -- o public_key_cloning.txt is output to the document.

The output document content is as follows. It is best to test it in small quantities and then produce it in large quantities when you think it is suitable.
```
022aa80995b3b9af2803c425e12e88471f2a2d1512528726ad2e15c3b0e3f7131b = + 22374041070950470002438945621627289646414
02c36bf4fbca5962a2dd31151442a514c36e26be4e1229e53ae3e7a81ad1646eb7 = - 22374041070950470002438945621627289646414
028fcf00b8a9d2f0935b56ba1a905746733a653414d58102018c7dc50e4410da16 = + 39928007492346635513395814867289295601574
029fc13c1a58c3a38c28cbdff9e27726e0245d094e09ca95ad358b34eb8cefe1cb = - 39928007492346635513395814867289295601574
0349678fb88cae8ecab898e3e2e2a1f42206584faee511bd2c867e36a3811f3647 = + 33844416032054525094006830048200806952865
038f022a83159518036d52e9c67d4d8f1474f310b7a385de799334adf71f3a78f0 = - 33844416032054525094006830048200806952865
03435ab2002c65cbd40a39bed824979acbb7d05f1dd92823eb7ec71196711be739 = + 37772688580381890451291531234834879471691
03e0b74145133f5df4131f9467f9d9e2ca179c7a29f029974dd44a72e7b1fb6365 = - 37772688580381890451291531234834879471691
.
.
.
03a3ecc4f9be3bdbd89cac9f9030635165834eadbdd8e5024a66a556a2591f4484 = + 34175422361938706507733670004697794783947
0396c4bf80ae2f7d18d9fae021caf6e7503f3bfa5323c1f0bf9edb2a1ace67d353 = - 34175422361938706507733670004697794783947
028eb82b574b42c35bd262892e179bda40fa190be79014640f25adb7d050fc6833 = + 29612023121674702203607464042707477088099
03ee026fd310fedbdf0ecbe1358110b7492adc59ca01b35e1f95e37b886624a118 = - 29612023121674702203607464042707477088099
02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16 = original
```
# The private key can be recovered by knowing the encoded cloned public key.

Then you need to use pubkey_calculator.c or calculator.c, which is a public key calculator or computer (decimal and hexadecimal can be converted to each other). Because our public key cloner encoding is in decimal, a conversion is required. Of course, when making a public key clone, its correctness also needs to be verified or verified through calculation. They are called PC and C programs.

example
```
./p 03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556 -b 3 -n 5 -R -v
[+] bits=3 → min=2^(3-1)=4, max=2^3-1=7
03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8 = + 7
0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 = - 7
03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb = + 5
0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 = - 5
03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7 = + 4
02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 = - 4
03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8 = + 7
0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 = - 7
03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb = + 5
0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 = - 5  ******（Assuming）例子
03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556 = original
```
Assuming that 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 is the cloned public key we generated, in the following example, -5 actually represents a number subtracted by 5, where 5 is the encoded number of the cloned public key, and 03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556 is our subject's original public key.
```
./pc 03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556 - 5
減法 結果(result): 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```
If we obtain the true private key corresponding to the public key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, how do we recover it?
Assuming you click it and obtain private key 1, you must use a computer to add back the subtracted value because it was subtracted from the main body. Therefore, you must add the encoding number 5 to return to the original value. Simply put, 6 - 5 = 1, so we need to add it back, 1 + 5 = 6, and then you can recover it. So let's use a calculator to compute it.
```
./c
Large integer calculator大整数进制计算器（C + GMP）
Supported operators: + - * / ，支持运算符：+  -  *  /
Type q or Q to quit输入 q 或 Q 退出
The default is decimal input, please start with 0x or 0X for hexadecimal.默认十进制输入，十六进制请以 0x 或 0X 开头

Please enter a value请输入数值：0x1 + 5
结果result (10Base进制)：6
结果result (16Base进制)：0x6
```
Note that it is in hexadecimal. This is an example so it will be clearer. You need to use a calculator because the value is encoded in decimal and needs to be entered in decimal. 
The private key is in hexadecimal and you need to add 0x to get the result 0x6, which is the original private key in hexadecimal.

We use key_homomorphism.c to verify that the private key corresponds to the public key. It is called the kh program. 
It uses the hexadecimal private key input to calculate the public key for each function.
```
./kh 6

输入enter私钥: 0000000000000000000000000000000000000000000000000000000000000006
原始original公钥: 03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556

公钥pub1 (Q)   : 03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556
公钥pub2 (-Q)   : 02fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556
公钥pub3 (φ(Q)): 03e63bcdd9aa535fc65e3aa731e3e8bed786649d3e56a15a6847aaf28078f38045
公钥pub4 (-φ(Q)): 02e63bcdd9aa535fc65e3aa731e3e8bed786649d3e56a15a6847aaf28078f38045
公钥pub5 (φ²(Q)): 0319cab650e04db19581801eb9e6c50b54f6a51b9223f6040c894f936926e302c3
公钥pub6 (-φ²(Q)): 0219cab650e04db19581801eb9e6c50b54f6a51b9223f6040c894f936926e302c3

私钥key1 (d)    : 0000000000000000000000000000000000000000000000000000000000000006
私钥key2 (n-d)  : fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413b
私钥key3 (lambda*d): f4560fcc82292543dee4a80f306e5a1db265f49613bfc6997a3d285bd2a02f6b
私钥key4 (n-lambda*d): 0ba9f0337dd6dabc211b57f0cf91a5e10848e8509b88d9a245953630fd9611d6
私钥key5 (lambda^2*d): 0ba9f0337dd6dabc211b57f0cf91a5e10848e8509b88d9a245953630fd9611d0
私钥key6 (n-lambda^2*d): f4560fcc82292543dee4a80f306e5a1db265f49613bfc6997a3d285bd2a02f71
```
Ok, it worked. Now you can convert it to an address using my other libraries, or convert it to a wallet private key and import it directly into your wallet.
https://github.com/8891689/Bitcoinkey-to-address
```
输入enter私钥: 0000000000000000000000000000000000000000000000000000000000000006
原始original公钥: 03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556
```

```
./key 6
WIF Private Key (Compressed): KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU76Myig6zj
WIF Private Key (Uncompressed): 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreBKdE2NK
Compressed Public Key: 03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556
Uncompressed Public Key: 04fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297
=== Addresses Generated from Compressed Public Key ===
P2PKH (Starts with 1) Address (Compressed): 1Cf2hs39Woi61YNkYGUAcohL2K2q4pawBq
P2SH (Starts with 3) Address (Compressed): 3LKyvRN6SmYXGBNn8fcQvYxW9MGKtwcinN (P2SH => P2WPKH)
Bech32 (Starts with bc1) Address (Compressed): bc1q0ldfeupqc9k2eaffep7cm6yml3ct3jwtwzqt7k
=== Addresses Generated from Uncompressed Public Key ===
P2PKH (Starts with 1) Address (Uncompressed): 1UCZSVufT1PNimutbPdJUiEyCYSiZAD6n
P2SH (Starts with 3) Address (Uncompressed): 3LSHGbG57JDvxuejpCQPJd5jwSTsnWVzxa (P2SH => P2WPKH)
Bech32 (Starts with bc1) Address (Uncompressed): bc1qq5jwz4q4lrsrspcm7mg0p4d29dzt7m8dpylunr
```

# The obtained address can be searched directly in the blockchain browser. Remember to replace the address, you can view many currencies with one click.

https://privatekeys.pw/address/bitcoin/1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH

or

https://www.oklink.com/zh-hans/all-chain

# Auxiliary advanced commands Debian/Ubuntu

1. Public_key_cloning.txt Search in Documentation 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

grep -B 1 "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" Public_key_cloning.txt

2. The Merge and Remove Duplicates command merges the two files 1.txt and 2.txt into one file 1.2.txt after removing duplicates.

cat 1.txt 2.txt | sort -u > 1.2.txt 

3. Remove duplicate commands to remove redundant data in the 1.txt document, such as addresses or public keys, and make it a unique 1.2.txt

sort -u 1.txt > 1.2.txt

4. Count the number of lines in the command 1.2.txt document.

wc -l 1.2.txt


5. Various addresses and hash values, as well as public key extraction commands, such as extracting only the address of the required length from the document, as well as the hash value 160, the public key, the document name in front, and the output name behind.

```
grep -o -E '1[a-zA-Z0-9]{25,34}' Bitcoin_addresses_LATEST.txt > bitcoin_addresses.txt            // For example, this command only extracts the address and length starting with 1.

grep -o -E 't[13][1-9A-HJ-NP-Za-km-z]{33,34}' blockchair_zcash_addresses_latest.tsv > zcash_addresses

grep -o -E '([LM][1-9A-HJ-NP-Za-km-z]{33}|ltc1[02-9ac-hj-np-z]{39,59})' blockchair_litecoin_addresses_latest.tsv > litecoin_addresses

grep -o -E '([DA9][1-9A-HJ-NP-Za-km-z]{25,34})' blockchair_dogecoin_addresses_latest.tsv > dogecoin_addresses

grep -o -E '([X7][1-9A-HJ-NP-Za-km-z]{33})' blockchair_dash_addresses_latest.tsv > dash_addresses

grep -o -E '([qp][0-9a-z]{42})' blockchair_bitcoin-cash_addresses_latest.tsv > cash_addresses
                                   ---------------------------------          ---------------
                                        Download document data from the website  >  Extract plain text address

grep -Eo '\b[a-fA-F0-9]{40}\b' bitcoin.160.txt > all.Bitcoin.160.txt     // This is the hash 160 of length 40 in the extracted document. Remove the redundant length and the non-conforming hash value.


grep -o -E '[0-9a-fA-F]{66}' b9b6d08d1e16.txt > 9b6d08d1e16.txt          //This is to extract the public key in the document that meets the length and prefix, and output it to a new document. Test the small data and extract it if it is suitable. If it is not suitable, ask AI to help you adjust it.

grep -o -E '0[23][0-9a-fA-F]{64}' b9b6d08d1e16.txt > 9b6d08d1e16.txt

grep -E '^[0-9a-fA-F]{66} = +' 189b3bc478.txt | grep -o -E '[0-9a-fA-F]{66}' > bc478.txt
```

6. If the file is too large, you can split it into two files, splitting 1.txt into 1_aa and 1_bb.

split -n 2 1 1_

1_aa
1_bb

# Acknowledgements

Author: 8891689

Assisted in creation: gemini ，ChatGPT，DeepSeek 。



# Sponsorship
If this project is helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!
```
BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4
```
# 📜 Disclaimer
This code is only for learning and understanding how it works.
Please make sure the program runs in a safe environment and comply with local laws and regulations!
The developer is not responsible for any financial losses or legal liabilities caused by the use of this code.
