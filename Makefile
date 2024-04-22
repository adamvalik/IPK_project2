# @file Makefile
# @author Adam Valík <xvalik05@vutbr.cz>

EXEC = ipk-sniffer
SRC = $(wildcard *.cpp)
OBJ = $(patsubst %.cpp,%.o,$(SRC))

CPP = g++
CPPFLAGS = -std=c++20

.PHONY: all clean doc

.DEFAULT_GOAL := all

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CPP) $(CPPFLAGS) -o $@ $^ -lpcap

%.o: %.cpp
	$(CPP) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f *.o $(EXEC)

pack: clean
	zip -r xvalik05.zip *.cpp *.hpp Makefile README.md CHANGELOG.md LICENSE Doxyfile SnifferUML.jpeg

doc: 
	doxygen Doxyfile
