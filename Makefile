CFLAGS = -g
CC = gcc

default: check

check: clean libckpt hello run_hello restart run_restart

run_hello:
	(sleep 3 && kill -12 `pgrep -n hello` && sleep 2 && pkill -9 -n hello) &
	./hello; true
	
run_restart:
	(sleep 3 &&  pkill -9 -n myrestart) &
	./myrestart myckpt; true

all: clean libckpt hello restart

libckpt:
	$(CC) $(CFLAGS) -c -o ckpt.o ckpt.c && ar rcs libckpt.a ckpt.o
	
hello:
	$(CC) $(CFLAGS) -static -L`pwd` -lckpt -Wl,-u,myconstructor hello.c -o hello
	
restart:
	$(CC) $(CFLAGS) -static -Wl,-Ttext-segment=5000000 -Wl,-Tdata=5100000 -Wl,-Tbss=5200000 myrestart.c -o myrestart -L`pwd` -lckpt

clean:
	rm -rf hello myrestart libckpt.a *.o myckpt

dist:
	dir=`basename $$PWD`; cd ..; tar cvf $$dir.tar ./$$dir; gzip $$dir.tar