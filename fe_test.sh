make -j12 && gcc ./src/tests_fe.c ./.libs/libsecp256k1.a -o tests_fe -I ./include && ./tests_fe