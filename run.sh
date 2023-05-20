# 第一次运行请运行命令安装相关软件并生成库文件
# sudo apt-get install autoreconf
# sudo apt-get install libtool
# ./autogen.sh && ./configure --with-ecmult-gen-kb=86 && make clean && make -j check &&
gcc -fopenmp ./src/sm2test.c ./.libs/libsecp256k1.a -o sm2_sign_test -I ./include && ./sm2_sign_test
gcc -fopenmp ./src/sm2_enc_and_dec_test.c ./.libs/libsecp256k1.a -o sm2_enc_test -I ./include && ./sm2_enc_test