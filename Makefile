all:
	gcc -O3 -s -w main.c aes.c -I check_speed.h aes.h lookup.h -o AES

clean:
	rm -rf AES
