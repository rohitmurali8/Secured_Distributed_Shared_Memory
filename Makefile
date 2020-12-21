all:
	gcc -O0 -g3 application.c -o application -lpthread -L . -l:libtomcrypt.a -I headers/ 
	gcc -O0 -g3 synflood.c -o synflood
clean:
	rm application synflood
