make -j12 && gcc ./src/tests_scalar.c ./.libs/libsecp256k1.a -o tests_scalar -I ./include && ./tests_scalar