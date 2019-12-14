SHELL = /bin/bash
CC = gcc
PP = g++
CFLAGS = -lpcap
SRCC = $(wildcard *.c)
SRCP = $(wildcard *.cpp)
EXEC = $(patsubst %.c, %, $(SRCC))
EXEP = $(patsubst %.cpp, %, $(SRCP))


all: ${EXEC}	${EXEP}

%:	%.cpp
	${PP} $@.cpp -o $@ ${CFLAGS}

%:	%.c
	${CC} $@.c -o $@ ${CFLAGS}

clean:
	rm ${EXEC}	${EXEP}
