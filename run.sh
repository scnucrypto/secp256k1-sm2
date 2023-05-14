# ./autogen.sh && ./configure --with-ecmult-gen-kb=86 && make clean && make -j check &&
gcc ./src/sm2test.c ./.libs/libsecp256k1.a -o sm2_sign_test -I ./include && ./sm2_sign_test
gcc ./src/sm2_enc_and_dec_test.c ./.libs/libsecp256k1.a -o sm2_enc_test -I ./include && ./sm2_enc_test