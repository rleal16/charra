
if [ $# -eq 1 ] && [ $1 = valgrind ] 
then
    (valgrind --leak-check=full --show-leak-kinds=all -v bin/attester 2> attester-valgrind-stderr.log &); sleep .2 ; (valgrind --leak-check=full --show-leak-kinds=all -v bin/verifier 2> verifier-valgrind-stderr.log) ; sleep 1 ; pkill -SIGINT -f bin/attester
elif [ $# -eq 1 ] && [ $1 = sanitize ]
then
    make clean ; make address-sanitizer=1
    (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT -f bin/attester
else
    echo $#
    make -j
    (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT attester
fi
