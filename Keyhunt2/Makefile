#---------------------------------------------------------------------
# Makefile for KeyHunt
#
# Author : Jean-Luc PONS

SRC = Base58.cpp IntGroup.cpp Main.cpp Bloom.cpp Random.cpp \
      Timer.cpp Int.cpp IntMod.cpp Point.cpp SECP256K1.cpp \
      KeyHunt.cpp GPU/GPUGenerate.cpp hash/ripemd160.cpp \
      hash/sha256.cpp hash/sha512.cpp hash/ripemd160_sse.cpp \
      hash/sha256_sse.cpp Bech32.cpp binToHex.cpp

OBJDIR = obj

ifdef gpu

OBJET = $(addprefix $(OBJDIR)/, \
        Base58.o IntGroup.o Main.o Bloom.o Random.o Timer.o Int.o \
        IntMod.o Point.o SECP256K1.o KeyHunt.o GPU/GPUGenerate.o \
        hash/ripemd160.o hash/sha256.o hash/sha512.o \
        hash/ripemd160_sse.o hash/sha256_sse.o \
        GPU/GPUEngine.o Bech32.o binToHex.o)

else

OBJET = $(addprefix $(OBJDIR)/, \
        Base58.o IntGroup.o Main.o Bloom.o Random.o Timer.o Int.o \
        IntMod.o Point.o SECP256K1.o KeyHunt.o GPU/GPUGenerate.o \
        hash/ripemd160.o hash/sha256.o hash/sha512.o \
        hash/ripemd160_sse.o hash/sha256_sse.o Bech32.o binToHex.o)

endif

CXX = g++
CUDA = /usr/local/cuda-11.0
CXXCUDA = /usr/bin/g++
NVCC = $(CUDA)/bin/nvcc
ccap = $(shell echo $(CCAP) | tr -d '.')

ifdef gpu
ifdef debug
CXXFLAGS = -DWITHGPU -m64 -mssse3 -Wno-write-strings -g -I. -I$(CUDA)/include
else
CXXFLAGS = -DWITHGPU -m64 -mssse3 -Wno-write-strings -O2 -I. -I$(CUDA)/include
endif
LFLAGS = -lpthread -L$(CUDA)/lib64 -lcudart
else
ifdef debug
CXXFLAGS = -m64 -mssse3 -Wno-write-strings -g -I.
else
CXXFLAGS = -m64 -mssse3 -Wno-write-strings -O2 -I.
endif
LFLAGS = -lpthread
endif

#--------------------------------------------------------------------

ifdef gpu
ifdef debug
$(OBJDIR)/GPU/GPUEngine.o: GPU/GPUEngine.cu
	$(NVCC) -G -maxrregcount=0 --ptxas-options=-v --compile --compiler-options -fPIC -ccbin $(CXXCUDA) -m64 -g -I$(CUDA)/include -gencode=arch=compute_$(ccap),code=sm_$(ccap) -o $(OBJDIR)/GPU/GPUEngine.o -c GPU/GPUEngine.cu
else
$(OBJDIR)/GPU/GPUEngine.o: GPU/GPUEngine.cu
	$(NVCC) -maxrregcount=0 --ptxas-options=-v --compile --compiler-options -fPIC -ccbin $(CXXCUDA) -m64 -O2 -I$(CUDA)/include -gencode=arch=compute_$(ccap),code=sm_$(ccap) -o $(OBJDIR)/GPU/GPUEngine.o -c GPU/GPUEngine.cu
endif
endif

$(OBJDIR)/%.o : %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

all: KeyHunt

KeyHunt: $(OBJET)
	@echo Making KeyHunt...
	$(CXX) $(OBJET) $(LFLAGS) -o KeyHunt

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/GPU: $(OBJDIR)
	mkdir -p $(OBJDIR)/GPU

$(OBJDIR)/hash: $(OBJDIR)
	mkdir -p $(OBJDIR)/hash

clean:
	@echo Cleaning...
	@rm -f $(OBJDIR)/*.o
	@rm -f $(OBJDIR)/GPU/*.o
	@rm -f $(OBJDIR)/hash/*.o
