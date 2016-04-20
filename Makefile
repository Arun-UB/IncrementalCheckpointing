CFLAGS = -g -std=gnu99
CC = gcc

default: all 

check: clean libckpt hello run_hello restart run_restart

run_hello:
	(sleep 3 && kill -12 `pgrep -n hello` && sleep 2 && pkill -9 -n hello) &
	./hello; true
	
run_restart:
	(sleep 3 &&  pkill -9 -n myrestart) &
	./myrestart myckpt; true

all: clean libckpt2 libckpt3 hello restart

libckpt:
	$(CC) $(CFLAGS) -c -o ckpt.o ckpt.c && ar rcs libckpt.a ckpt.o

libckpt2:
	$(CC) $(CFLAGS) -I/usr/local/include/ -Wall -c -o ckpt.o ckpt.c && ar rcs libckpt.a ckpt.o
	
libckpt3:
	$(CC) $(CFLAGS) -I/usr/local/include/ -Wall -c -o ckpt_restart.o ckpt_restart.c && ar rcs libckpt3.a ckpt_restart.o
	
hello:
	$(CC) $(CFLAGS) -L`pwd` -lckpt -lgit2 -Wl,-u,myconstructor hello.c -o hello
	
restart:
	$(CC) $(CFLAGS) -static -Wl,-Ttext-segment=5000000 -Wl,-Tdata=5100000 -Wl,-Tbss=5200000 myrestart.c -o myrestart -L`pwd` -lckpt3 -lc

clean:
	rm -rf hello myrestart libckpt.a *.o myckpt

dist:
	dir=`basename $$PWD`; cd ..; tar cvf $$dir.tar ./$$dir; gzip $$dir.tar
