CC = gcc
BUILD_DIR=build

default: compile run

compile:
	@mkdir -p $(BUILD_DIR)
	$(CC) -I./include -o $(BUILD_DIR)/main src/* -lcrypto 

run: $(BUILD_DIR)
	./$(BUILD_DIR)/main hello