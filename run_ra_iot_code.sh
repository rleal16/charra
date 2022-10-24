
if [ $# -eq 1 ] && [ $1 = valgrind ] 
then
    (valgrind --leak-check=full --show-leak-kinds=all -v bin/ra_iot_attester 2> ra_iot_attester-valgrind-stderr.log &); sleep .2 ; (valgrind --leak-check=full --show-leak-kinds=all -v bin/ra_iot_verifier 2> ra_iot_verifier-valgrind-stderr.log) ; sleep 1 ; pkill -SIGINT -f bin/ra_iot_attester
elif [ $# -eq 1 ] && [ $1 = sanitize ]
then
    make clean ; make address-sanitizer=1
    (bin/ra_iot_attester &); sleep .2 ; bin/ra_iot_verifier ; sleep 1 ; pkill -SIGINT -f bin/ra_iot_attester
else
    echo $#
    make -j
    (bin/ra_iot_attester &); sleep .2 ; bin/ra_iot_verifier ; sleep 1 ; pkill -SIGINT ra_iot_attester
fi
