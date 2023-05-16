NAME = signtool
CC = gcc

UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
	LINK = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
	INCLUDE = -I./include -I/opt/homebrew/opt/openssl@3/include
else
	LINK = -lssl -lcrypto
	INCLUDE = -I./include
endif

SRCS_DIR = ./src
SRCS = src/main.c \
		src/4109.c \
		src/signtool.c \
		src/file.c \
		src/init.c \
		src/parse.c \
		src/print.c

OBJS = $(SRCS:.c=.o)

$(NAME) : $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LINK)

%.o : %.c
	$(CC) $(INCLUDE) -c $< -o $@

all : $(NAME)

clean :
	$(RM) $(OBJS)

fclean : clean
	$(RM) $(NAME)

re : 
	make fclean
	make all

.PHONY: all clean fclean re
