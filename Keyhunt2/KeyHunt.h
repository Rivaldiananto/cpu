#ifndef _KEYHUNT_H_
#define _KEYHUNT_H_

#include <string>
#include <vector>
#include <cstdint>
#include "Int.h"
#include "Point.h"
#include "Secp256K1.h"
#include "Bloom.h"

#define CPU_GRP_SIZE 1024

enum SEARCH_MODE {
    SEARCH_COMPRESSED = 1,
    SEARCH_UNCOMPRESSED,
    SEARCH_BOTH
};

enum SEARCH_TYPE {
    P2PKH = 1,
    P2SH,
    BECH32
};

enum ADDRESS_MODE {
    FILEMODE = 1,
    SINGLEMODE
};

typedef struct {
    int threadId;
    Int rangeStart;
    Int rangeEnd;
    bool isRunning;
    bool hasStarted;
    int gpuId;
    int gridSizeX;
    int gridSizeY;
    class KeyHunt* obj;
} TH_PARAM;

class KeyHunt {
public:
    KeyHunt(const std::string& addressFile, const std::vector<unsigned char>& addressHash,
        int searchMode, bool useGpu, const std::string& outputFile, bool useSSE,
        uint32_t maxFound, const std::string& rangeStart, const std::string& rangeEnd,
        bool& should_exit);
    ~KeyHunt();

    void Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit);
    static std::string GetHex(std::vector<unsigned char>& buffer);

private:
    void getCPUStartingKey(int thId, Int& tRangeStart, Int& key, Point& startP);
    void FindKeyCPU(TH_PARAM* ph);
    void getGPUStartingKeys(int thId, Int& tRangeStart, Int& tRangeEnd, int groupSize, int nbThread, Int* keys, Point* p);
    void FindKeyGPU(TH_PARAM* ph);
    bool checkPrivKey(std::string addr, Int& key, int32_t incr, bool mode);
    void checkAddresses(bool compressed, Int key, int i, Point p1);
    void checkAddresses2(bool compressed, Int key, int i, Point p1);
    void checkAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4);
    void checkAddressesSSE2(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4);
    bool isAlive(TH_PARAM* p);
    bool hasStarted(TH_PARAM* p);
    uint64_t getGPUCount();
    uint64_t getCPUCount();
    void SetupRanges(uint32_t totalThreads);
    void output(std::string addr, std::string pAddr, std::string pAddrHex);
    int CheckBloomBinary(const uint8_t* hash);
    bool MatchHash160(uint32_t* _h);
    std::string formatThousands(uint64_t x);
    char* toTimeStr(int sec, char* timeStr);

    // Deklarasi fungsi baru
    std::string binToHex(const std::string& bin);
    void generateHexRange(const std::string& startBin, const std::string& endBin, std::vector<std::string>& hexRange);

    // Data members
    int searchMode;
    bool useGpu;
    std::string outputFile;
    bool useSSE;
    int nbGPUThread;
    std::string addressFile;
    uint32_t maxFound;
    int searchType;
    Int rangeStart;
    Int rangeEnd;
    Int rangeDiff2;
    Int rangeDiff;
    int addressMode;
    std::vector<unsigned char> hash160;
    Bloom* bloom;
    Secp256K1* secp;
    uint8_t* DATA;
    uint64_t BLOOM_N;
    uint64_t TOTAL_ADDR;
    uint64_t counters[CPU_GRP_SIZE];
    bool endOfSearch;
    double startTime;

#ifdef WIN64
    HANDLE ghMutex;
#else
    pthread_mutex_t ghMutex;
#endif
};

#endif // _KEYHUNT_H_
