./autogen.sh && ./configure --with-ecmult-gen-kb=86 && make clean && make
gcc ./src/sm2test.c ./.libs/libsecp256k1.so -o sm2 && ./sm2	
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/zyp/secp256k1-sm/.libs
cp .libs/* ../wbcryptlib/jna/
cd ../wbcryptlib/jna/ && bash build.sh
cd 

gcc -I./include ./src/sm2_enc_and_dec_test.c ./.libs/libsecp256k1.a -o sm2 && ./sm2	
make && gcc -I./include ./src/sm2_enc_and_dec_test.c ./.libs/libsecp256k1.a -o sm2 && ./sm2