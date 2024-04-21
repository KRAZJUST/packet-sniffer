CC = g++
CFLAGS = -std=c++20 -Wall
LDFLAGS = -lpcap

SRC_DIR = src
BIN_DIR = bin

# Create the BIN_DIR if it doesn't exist
$(shell mkdir -p $(BIN_DIR))

SOURCES=$(wildcard $(SRC_DIR)/*.cpp)
OBJECTS=$(patsubst $(SRC_DIR)/%.cpp,$(BIN_DIR)/%.o,$(SOURCES))
EXECUTABLE=ipk-sniffer

.PHONY: all clean

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BIN_DIR)/*.o $(EXECUTABLE)
