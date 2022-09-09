##cd ../mbedtls/
##make
##cd ../test_ra_iot/
##gcc -Wall ../mbedtls/library/*.c *.c -g -o test
#valgrind --leak-check=full --show-leak-kinds=all -v ./test
#./test

gcc -I ../mbedtls/include -c *.c
gcc -L`pwd`/library -o my_test *.o -l mbedtls