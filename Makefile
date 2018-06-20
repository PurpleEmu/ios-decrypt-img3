CXX=g++
CFLAGS=-std=c++14 -g -msse2 -msse -march=native -maes
LIBS= -lssl -lcrypto
OBJ = main.o

all: $(OBJ)
	$(CXX) $(CFLAGS) $(OBJ) -o decryptimg3 $(LIBS)

clean:
	rm *.o && rm decryptimg3

%.o: %.cpp
	$(CXX) $(CFLAGS) -c $<