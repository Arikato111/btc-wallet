CC = gcc
BUILD_DIR=build
BUILD_FILE=bitcoin

default: compile

compile:
	@mkdir -p $(BUILD_DIR)
	$(CC) -I./include -o $(BUILD_DIR)/$(BUILD_FILE) src/* -lcrypto 

run: $(BUILD_DIR)
	./$(BUILD_DIR)/$(BUILD_FILE) hello

t:
	@if [ -f ./test.c ]; then \
		$(CC) -o test test.c  -lssl -lcrypto; \
		./test; \
	else \
		echo not found 'test.c'; \
	fi 