cpp curve25519-donna-x86-64.s > curve25519-donna-x86-64.s.pp
as -o curve25519-donna-x86-64.s.o curve25519-donna-x86-64.s.pp
gcc -std=c99 -Ofast -fomit-frame-pointer -c curve25519-donna-x86-64.c
gcc -std=c99 -Ofast -fomit-frame-pointer bruteforcer.c sha256-64.S curve25519-donna-x86-64.o curve25519-donna-x86-64.s.o -pthread -lncurses -o bruteforcer
