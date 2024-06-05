
# Makefile for KeyHunt-Cuda-2 CPU-only build

CXX = g++
CXXFLAGS = -O3 -Wall -Wextra
SRCS = main.cpp # Replace with actual source files
OBJS = $(SRCS:.cpp=.o)

all: keyhunt

keyhunt: $(OBJS)
	$(CXX) -o keyhunt $(OBJS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f *.o keyhunt
