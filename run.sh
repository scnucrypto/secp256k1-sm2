#!/bin/bash

# 第一次运行请运行命令安装相关软件并生成库文件
# sudo apt-get install autoreconf
# sudo apt-get install libtool
# ./autogen.sh && ./configure --with-ecmult-gen-kb=86 && make clean && make -j check && make

# 检查是否提供了至少一个命令行参数
if [ $# -eq 0 ]; then
  echo "Usage: bash $0 sign|enc|cosign|codec,"
  echo "Such as: bash test.sh sign"
  exit 1
fi

# 获取和使用命令行参数
echo "[+] run sm2_$1"

make clean && make -j12

if [ $1 = "sign" ]; then
    gcc -fopenmp ./src/sm2test.c ./.libs/libsecp256k1.a -o sm2_sign_test -I ./include && ./sm2_sign_test
elif [ $1 = "enc" ]; then
    gcc -fopenmp ./src/sm2_enc_and_dec_test.c ./.libs/libsecp256k1.a -o sm2_enc_test -I ./include && ./sm2_enc_test
elif [ $1 = "cosign" ]; then
    gcc -fopenmp ./src/sm2coop_test.c ./.libs/libsecp256k1.a -o sm2coop_sign_test -I ./include && ./sm2coop_sign_test
elif [ $1 = "codec" ]; then
    gcc -fopenmp ./src/sm2coop_dec_test.c ./.libs/libsecp256k1.a -o sm2coop_dec_test -I ./include && ./sm2coop_dec_test
fi