#include "KeyHunt.h"
#include "Base58.h"
#include "Bech32.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "IntGroup.h"
#include "Timer.h"
#include "hash/ripemd160.h"
#include <sstream>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iostream>
#ifndef WIN64
#include <pthread.h>
#endif
#include <bitset>

using namespace std;

Point Gn[CPU_GRP_SIZE / 2];
Point _2Gn;

// Fungsi untuk mengonversi string biner ke string hexadecimal
std::string binaryToHex(const std::string& binaryStr) {
    std::stringstream ss;
    ss << std::hex << std::stoull(binaryStr, nullptr, 2);
    return ss.str();
}

// Fungsi untuk mengonversi string hexadecimal ke string biner
std::string hexToBinary(const std::string& hex) {
    std::string binaryStr = "";
    for (char const &c : hex) {
        switch(c) {
            case '0': binaryStr.append("0000"); break;
            case '1': binaryStr.append("0001"); break;
            case '2': binaryStr.append("0010"); break;
            case '3': binaryStr.append("0011"); break;
            case '4': binaryStr.append("0100"); break;
            case '5': binaryStr.append("0101"); break;
            case '6': binaryStr.append("0110"); break;
            case '7': binaryStr.append("0111"); break;
            case '8': binaryStr.append("1000"); break;
            case '9': binaryStr.append("1001"); break;
            case 'A': case 'a': binaryStr.append("1010"); break;
            case 'B': case 'b': binaryStr.append("1011"); break;
            case 'C': case 'c': binaryStr.append("1100"); break;
            case 'D': case 'd': binaryStr.append("1101"); break;
            case 'E': case 'e': binaryStr.append("1110"); break;
            case 'F': case 'f': binaryStr.append("1111"); break;
            default: throw std::invalid_argument("Invalid hexadecimal character");
        }
    }
    return binaryStr;
}

// Fungsi untuk menambah nilai biner
std::string addBinary(const std::string& binaryStr, uint64_t value) {
    uint64_t binaryValue = std::stoull(binaryStr, nullptr, 2);
    binaryValue += value;
    return std::bitset<256>(binaryValue).to_string(); // Sesuaikan ukuran bit sesuai kebutuhan Anda
}

// Modifikasi pada konstruktor KeyHunt
KeyHunt::KeyHunt(const std::string& addressFile, const std::vector<unsigned char>& addressHash,
    int searchMode, bool useGpu, const std::string& outputFile, bool useSSE,
    uint32_t maxFound, const std::string& rangeStart, const std::string& rangeEnd,
    bool& should_exit)
{
    this->searchMode = searchMode;
    this->useGpu = useGpu;
    this->outputFile = outputFile;
    this->useSSE = useSSE;
    this->nbGPUThread = 0;
    this->addressFile = addressFile;
    this->maxFound = maxFound;
    this->searchType = P2PKH;

    // Simpan rentang dalam format biner
    this->rangeStartBinary = hexToBinary(rangeStart);
    if (rangeEnd.length() <= 0) {
        this->rangeEndBinary = addBinary(this->rangeStartBinary, 10000000000000000);
    } else {
        this->rangeEndBinary = hexToBinary(rangeEnd);
        if (binaryToHex(this->rangeEndBinary) < binaryToHex(this->rangeStartBinary)) {
            printf("Start range is bigger than end range, so flipping ranges.\n");
            std::swap(this->rangeStartBinary, this->rangeEndBinary);
        }
    }
    this->rangeDiffBinary = addBinary(this->rangeEndBinary, -std::stoull(this->rangeStartBinary, nullptr, 2));

    // Konversi rentang biner ke hexadecimal untuk pemrosesan lebih lanjut
    this->rangeStart.SetBase16(binaryToHex(this->rangeStartBinary).c_str());
    this->rangeEnd.SetBase16(binaryToHex(this->rangeEndBinary).c_str());
    this->rangeDiff2.SetBase16(binaryToHex(this->rangeDiffBinary).c_str());

    this->addressMode = FILEMODE;
    if (addressHash.size() > 0 && this->addressFile.length() <= 0)
        this->addressMode = SINGLEMODE;

    secp = new Secp256K1();
    secp->Init();

    if (this->addressMode == FILEMODE) {
        // load address file
        uint8_t buf[20];
        FILE* wfd;
        uint64_t N = 0;

        wfd = fopen(this->addressFile.c_str(), "rb");
        if (!wfd) {
            printf("%s can not open\n", this->addressFile.c_str());
            exit(1);
        }
#ifdef WIN64
        _fseeki64(wfd, 0, SEEK_END);
        N = _ftelli64(wfd);
#else
        fseek(wfd, 0, SEEK_END);
        N = ftell(wfd);
#endif
        N = N / 20;
        rewind(wfd);

        DATA = (uint8_t*)malloc(N * 20);
        memset(DATA, 0, N * 20);

        bloom = new Bloom(2 * N, 0.000001);

        uint64_t percent = (N - 1) / 100;
        uint64_t i = 0;
        printf("\n");
        while (i < N && !should_exit) {
            memset(buf, 0, 20);
            memset(DATA + (i * 20), 0, 20);
            if (fread(buf, 1, 20, wfd) == 20) {
                bloom->add(buf, 20);
                memcpy(DATA + (i * 20), buf, 20);
                if (i % percent == 0) {
                    printf("\rLoading      : %llu %%", (i / percent));
                    fflush(stdout);
                }
            }
            i++;
        }
        printf("\n");
        fclose(wfd);

        if (should_exit) {
            delete secp;
            delete bloom;
            if (DATA)
                free(DATA);
            exit(0);
        }

        BLOOM_N = bloom->get_bytes();
        TOTAL_ADDR = N;
        printf("Loaded       : %s address\n", formatThousands(i).c_str());
        printf("\n");

        bloom->print();
        printf("\n");
    } else {
        for (size_t i = 0; i < addressHash.size(); i++) {
            ((uint8_t*)hash160)[i] = addressHash.at(i);
        }
        printf("\n");
    }

    // Compute Generator table G[n] = (n+1)*G
    Point g = secp->G;
    Gn[0] = g;
    g = secp->DoubleDirect(g);
    Gn[1] = g;
    for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
        g = secp->AddDirect(g, secp->G);
        Gn[i] = g;
    }
    // _2Gn = CPU_GRP_SIZE*G
    _2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);

    char* ctimeBuff;
    time_t now = time(NULL);
    ctimeBuff = ctime(&now);
    printf("Start Time   : %s", ctimeBuff);

    printf("Global start : %s (%d bit)\n", rangeStart.c_str(), this->rangeStart.GetBitLength());
    printf("Global end   : %s (%d bit)\n", rangeEnd.c_str(), this->rangeEnd.GetBitLength());
    printf("Global range : %s (%d bit)\n", hexToBinary(this->rangeDiff2.GetBase16()).c_str(), this->rangeDiff2.GetBitLength());
}

KeyHunt::~KeyHunt()
{
    delete secp;
    if (this->addressMode == FILEMODE)
        delete bloom;
    if (DATA)
        free(DATA);
}

// Modifikasi pada fungsi FindKeyCPU
void KeyHunt::FindKeyCPU(TH_PARAM * ph)
{
    // Global init
    int thId = ph->threadId;
    std::string tRangeStartBinary = ph->rangeStartBinary;
    std::string tRangeEndBinary = ph->rangeEndBinary;
    counters[thId] = 0;

    // CPU Thread
    IntGroup* grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);

    // Group Init
    std::string keyBinary = tRangeStartBinary;
    Int key;
    key.SetBase16(binaryToHex(keyBinary).c_str());
    Point startP = secp->ComputePublicKey(&key);

    ph->hasStarted = true;

    while (!endOfSearch) {
        // Fill group
        int i;
        int hLength = (CPU_GRP_SIZE / 2 - 1);

        for (i = 0; i < hLength; i++) {
            dx[i].ModSub(&Gn[i].x, &startP.x);
        }
        dx[i].ModSub(&Gn[i].x, &startP.x);  // For the first point
        dx[i + 1].ModSub(&_2Gn.x, &startP.x); // For the next center point

        // Grouped ModInv
        grp->ModInv();

        // We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
        // We compute key in the positive and negative way from the center of the group

        // center point
        pts[CPU_GRP_SIZE / 2] = startP;

        for (i = 0; i < hLength && !endOfSearch; i++) {
            pp = startP;
            pn = startP;

            // P = startP + i*G
            dy.ModSub(&Gn[i].y, &pp.y);

            _s.ModMulK1(&dy, &dx[i]);       // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
            _p.ModSquareK1(&_s);            // _p = pow2(s)

            pp.x.ModNeg();
            pp.x.ModAdd(&_p);
            pp.x.ModSub(&Gn[i].x);           // rx = pow2(s) - p1.x - p2.x;

            pp.y.ModSub(&Gn[i].x, &pp.x);
            pp.y.ModMulK1(&_s);
            pp.y.ModSub(&Gn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);

            // P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
            dyn.Set(&Gn[i].y);
            dyn.ModNeg();
            dyn.ModSub(&pn.y);

            _s.ModMulK1(&dyn, &dx[i]);      // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
            _p.ModSquareK1(&_s);            // _p = pow2(s)

            pn.x.ModNeg();
            pn.x.ModAdd(&_p);
            pn.x.ModSub(&Gn[i].x);          // rx = pow2(s) - p1.x - p2.x;

            pn.y.ModSub(&Gn[i].x, &pn.x);
            pn.y.ModMulK1(&_s);
            pn.y.ModAdd(&Gn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);

            pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
            pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
        }

        // First point (startP - (GRP_SZIE/2)*G)
        pn = startP;
        dyn.Set(&Gn[i].y);
        dyn.ModNeg();
        dyn.ModSub(&pn.y);

        _s.ModMulK1(&dyn, &dx[i]);
        _p.ModSquareK1(&_s);

        pn.x.ModNeg();
        pn.x.ModAdd(&_p);
        pn.x.ModSub(&Gn[i].x);

        pn.y.ModSub(&Gn[i].x, &pn.x);
        pn.y.ModMulK1(&_s);
        pn.y.ModAdd(&Gn[i].y);

        pts[0] = pn;

        // Next start point (startP + GRP_SIZE*G)
        pp = startP;
        dy.ModSub(&_2Gn.y, &pp.y);

        _s.ModMulK1(&dy, &dx[i + 1]);
        _p.ModSquareK1(&_s);

        pp.x.ModNeg();
        pp.x.ModAdd(&_p);
        pp.x.ModSub(&_2Gn.x);

        pp.y.ModSub(&_2Gn.x, &pp.x);
        pp.y.ModMulK1(&_s);
        pp.y.ModSub(&_2Gn.y);
        startP = pp;

        // Check addresses
        if (useSSE) {
            for (int i = 0; i < CPU_GRP_SIZE && !endOfSearch; i += 4) {
                switch (searchMode) {
                    case SEARCH_COMPRESSED:
                        if (addressMode == FILEMODE)
                            checkAddressesSSE(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
                        else
                            checkAddressesSSE2(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
                        break;
                    case SEARCH_UNCOMPRESSED:
                        if (addressMode == FILEMODE)
                            checkAddressesSSE(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
                        else
                            checkAddressesSSE2(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
                        break;
                    case SEARCH_BOTH:
                        if (addressMode == FILEMODE) {
                            checkAddressesSSE(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
                            checkAddressesSSE(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
                        } else {
                            checkAddressesSSE2(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
                            checkAddressesSSE2(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
                        }
                        break;
                }
            }
        } else {
            for (int i = 0; i < CPU_GRP_SIZE && !endOfSearch; i++) {
                switch (searchMode) {
                    case SEARCH_COMPRESSED:
                        if (addressMode == FILEMODE)
                            checkAddresses(true, key, i, pts[i]);
                        else
                            checkAddresses2(true, key, i, pts[i]);
                        break;
                    case SEARCH_UNCOMPRESSED:
                        if (addressMode == FILEMODE)
                            checkAddresses(false, key, i, pts[i]);
                        else
                            checkAddresses2(false, key, i, pts[i]);
                        break;
                    case SEARCH_BOTH:
                        if (addressMode == FILEMODE) {
                            checkAddresses(true, key, i, pts[i]);
                            checkAddresses(false, key, i, pts[i]);
                        } else {
                            checkAddresses2(true, key, i, pts[i]);
                            checkAddresses2(false, key, i, pts[i]);
                        }
                        break;
                }
            }
        }

        // Perbarui kunci dalam format biner dan konversi ke hex
        keyBinary = addBinary(keyBinary, CPU_GRP_SIZE);
        key.SetBase16(binaryToHex(keyBinary).c_str());
        counters[thId] += CPU_GRP_SIZE; // Point
    }
    ph->isRunning = false;
}

// Modifikasi pada fungsi FindKeyGPU
void KeyHunt::FindKeyGPU(TH_PARAM * ph)
{
    bool ok = true;

#ifdef WITHGPU

    // Global init
    int thId = ph->threadId;
    std::string tRangeStartBinary = ph->rangeStartBinary;
    std::string tRangeEndBinary = ph->rangeEndBinary;

    GPUEngine* g;

    if (addressMode == FILEMODE) {
        g = new GPUEngine(ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, BLOOM_N, bloom->get_bits(),
            bloom->get_hashes(), bloom->get_bf(), DATA, TOTAL_ADDR);
    } else {
        g = new GPUEngine(ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, hash160);
    }

    int nbThread = g->GetNbThread();
    Point* p = new Point[nbThread];
    Int* keys = new Int[nbThread];
    vector<ITEM> found;

    printf("GPU          : %s\n\n", g->deviceName.c_str());

    counters[thId] = 0;

    g->SetSearchMode(searchMode);
    g->SetSearchType(searchType);
    g->SetAddressMode(addressMode);

    getGPUStartingKeys(thId, tRangeStartBinary, tRangeEndBinary, g->GetGroupSize(), nbThread, keys, p);
    ok = g->SetKeys(p);

    ph->hasStarted = true;

    // GPU Thread
    while (ok && !endOfSearch) {
        // Call kernel
        if (addressMode == FILEMODE) {
            ok = g->Launch(found, false);
        } else {
            ok = g->Launch2(found, false);
        }
        for (int i = 0; (int)found.size() && !endOfSearch; i++) {
            ITEM it = found[i];
            string addr = secp->GetAddress(searchType, it.mode, it.hash);
            if (checkPrivKey(addr, keys[it.thId], it.incr, it.mode)) {
                nbFoundKey++;
            }
        }

        if (ok) {
            for (int i = 0; i < nbThread; i++) {
                keys[i].Add((uint64_t)STEP_SIZE);
            }
            counters[thId] += (uint64_t)(STEP_SIZE)*nbThread; // Point
        }
    }

    delete[] keys;
    delete[] p;
    delete g;

#else
    ph->hasStarted = true;
    printf("GPU code not compiled, use -DWITHGPU when compiling.\n");
#endif

    ph->isRunning = false;
}

// Fungsi tambahan untuk mendapatkan kunci awal GPU dalam format biner
void KeyHunt::getGPUStartingKeys(int thId, std::string& tRangeStartBinary, std::string& tRangeEndBinary, int groupSize, int nbThread, Int* keys, Point* p)
{
    Int tRangeStart, tRangeEnd, tRangeDiff, tRangeStart2, tRangeEnd2;
    tRangeStart.SetBase16(binaryToHex(tRangeStartBinary).c_str());
    tRangeEnd.SetBase16(binaryToHex(tRangeEndBinary).c_str());

    tRangeDiff.Set(&tRangeEnd);
    tRangeDiff.Sub(&tRangeStart);

    tRangeStart2.Set(&tRangeStart);
    tRangeEnd2.Set(&tRangeStart);

    tRangeDiff.DivInt64(nbThread);

    for (int i = 0; i < nbThread; i++) {
        keys[i].Set(&tRangeStart2);
        tRangeEnd2.Set(&tRangeStart2);
        tRangeEnd2.Add(&tRangeDiff);
        tRangeStart2.Add(&tRangeDiff);

        Int k(keys + i);
        k.Add((uint64_t)(groupSize / 2));
        p[i] = secp->ComputePublicKey(&k);
    }
}

void KeyHunt::SetupRanges(uint32_t totalThreads)
{
    Int threads;
    threads.SetInt32(totalThreads);
    rangeDiff.Set(&rangeEnd);
    rangeDiff.Sub(&rangeStart);
    if (threads.IsZero()) {
        printf("Error: Number of threads is zero, cannot divide range.\n");
        exit(1);
    }
    rangeDiff.Div(&threads);
}

void KeyHunt::Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit)
{
    double t0;
    double t1;
    endOfSearch = false;
    nbCPUThread = nbThread;
    nbGPUThread = (useGpu ? (int)gpuId.size() : 0);
    nbFoundKey = 0;

    // setup ranges
    SetupRanges(nbCPUThread + nbGPUThread);

    memset(counters, 0, sizeof(counters));

    if (!useGpu)
        printf("\n");

    TH_PARAM* params = (TH_PARAM*)malloc((nbCPUThread + nbGPUThread) * sizeof(TH_PARAM));
    memset(params, 0, (nbCPUThread + nbGPUThread) * sizeof(TH_PARAM));

    int rangeShowThreasold = 3;
    int rangeShowCounter = 0;

    // Launch CPU threads
    for (int i = 0; i < nbCPUThread; i++) {
        params[i].obj = this;
        params[i].threadId = i;
        params[i].isRunning = true;

        params[i].rangeStart.Set(&rangeStart);
        params[i].rangeStartBinary = rangeStartBinary;
        rangeStart.Add(&rangeDiff);
        params[i].rangeEnd.Set(&rangeStart);
        params[i].rangeEndBinary = binaryToHex(rangeEndBinary);

        if (i < rangeShowThreasold) {
            printf("CPU Thread %02d: %s : %s\n", i, hexToBinary(params[i].rangeStart.GetBase16()).c_str(), hexToBinary(params[i].rangeEnd.GetBase16()).c_str());
        } else if (rangeShowCounter < 1) {
            printf("             .\n");
            rangeShowCounter++;
            if (i + 1 == nbCPUThread) {
                printf("CPU Thread %02d: %s : %s\n", i, hexToBinary(params[i].rangeStart.GetBase16()).c_str(), hexToBinary(params[i].rangeEnd.GetBase16()).c_str());
            }
        } else if (i + 1 == nbCPUThread) {
            printf("CPU Thread %02d: %s : %s\n", i, hexToBinary(params[i].rangeStart.GetBase16()).c_str(), hexToBinary(params[i].rangeEnd.GetBase16()).c_str());
        }

#ifdef WIN64
        DWORD thread_id;
        CreateThread(NULL, 0, _FindKey, (void*)(params + i), 0, &thread_id);
        ghMutex = CreateMutex(NULL, FALSE, NULL);
#else
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, &_FindKey, (void*)(params + i));
        ghMutex = PTHREAD_MUTEX_INITIALIZER;
#endif
    }

    // Launch GPU threads
    for (int i = 0; i < nbGPUThread; i++) {
        params[nbCPUThread + i].obj = this;
        params[nbCPUThread + i].threadId = 0x80L + i;
        params[nbCPUThread + i].isRunning = true;
        params[nbCPUThread + i].gpuId = gpuId[i];
        params[nbCPUThread + i].gridSizeX = gridSize[2 * i];
        params[nbCPUThread + i].gridSizeY = gridSize[2 * i + 1];

        params[nbCPUThread + i].rangeStart.Set(&rangeStart);
        params[nbCPUThread + i].rangeStartBinary = rangeStartBinary;
        rangeStart.Add(&rangeDiff);
        params[nbCPUThread + i].rangeEnd.Set(&rangeStart);
        params[nbCPUThread + i].rangeEndBinary = binaryToHex(rangeEndBinary);

#ifdef WIN64
        DWORD thread_id;
        CreateThread(NULL, 0, _FindKeyGPU, (void*)(params + (nbCPUThread + i)), 0, &thread_id);
#else
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, &_FindKeyGPU, (void*)(params + (nbCPUThread + i)));
#endif
    }

#ifndef WIN64
    setvbuf(stdout, NULL, _IONBF, 0);
#endif
    printf("\n");

    uint64_t lastCount = 0;
    uint64_t gpuCount = 0;
    uint64_t lastGPUCount = 0;

    // Key rate smoothing filter
#define FILTER_SIZE 8
    double lastkeyRate[FILTER_SIZE];
    double lastGpukeyRate[FILTER_SIZE];
    uint32_t filterPos = 0;

    double keyRate = 0.0;
    double gpuKeyRate = 0.0;
    char timeStr[256];

    memset(lastkeyRate, 0, sizeof(lastkeyRate));
    memset(lastGpukeyRate, 0, sizeof(lastkeyRate));

    // Wait that all threads have started
    while (!hasStarted(params)) {
        Timer::SleepMillis(500);
    }

    // Reset timer
    Timer::Init();
    t0 = Timer::get_tick();
    startTime = t0;
    Int p100;
    Int ICount;
    p100.SetInt32(100);

    while (isAlive(params)) {
        int delay = 2000;
        while (isAlive(params) && delay > 0) {
            Timer::SleepMillis(500);
            delay -= 500;
        }

        gpuCount = getGPUCount();
        uint64_t count = getCPUCount() + gpuCount;
        ICount.SetInt64(count);
        int completedBits = ICount.GetBitLength();
        ICount.Mult(&p100);
        ICount.Div(&this->rangeDiff2);
        int completed = std::stoi(ICount.GetBase10());

        t1 = Timer::get_tick();
        keyRate = (double)(count - lastCount) / (t1 - t0);
        gpuKeyRate = (double)(gpuCount - lastGPUCount) / (t1 - t0);
        lastkeyRate[filterPos % FILTER_SIZE] = keyRate;
        lastGpukeyRate[filterPos % FILTER_SIZE] = gpuKeyRate;
        filterPos++;

        // KeyRate smoothing
        double avgKeyRate = 0.0;
        double avgGpuKeyRate = 0.0;
        uint32_t nbSample;
        for (nbSample = 0; (nbSample < FILTER_SIZE) && (nbSample < filterPos); nbSample++) {
            avgKeyRate += lastkeyRate[nbSample];
            avgGpuKeyRate += lastGpukeyRate[nbSample];
        }
        avgKeyRate /= (double)(nbSample);
        avgGpuKeyRate /= (double)(nbSample);

        if (isAlive(params)) {
            memset(timeStr, '\0', 256);
            printf("\r[%s] [CPU+GPU: %.2f Mk/s] [GPU: %.2f Mk/s] [C: %d%%] [T: %s (%d bit)] [F: %d]  ",
                toTimeStr(t1, timeStr),
                avgKeyRate / 1000000.0,
                avgGpuKeyRate / 1000000.0,
                completed,
                formatThousands(count).c_str(),
                completedBits,
                nbFoundKey);
        }

        lastCount = count;
        lastGPUCount = gpuCount;
        t0 = t1;
        if (should_exit || (addressMode == FILEMODE ? false : (nbFoundKey > 0)))
            endOfSearch = true;
    }

    free(params);
}

bool KeyHunt::checkPrivKey(string addr, Int& key, int32_t incr, bool mode)
{
    Int k(&key);
    k.Add((uint64_t)incr);

    // Check addresses
    Point p = secp->ComputePublicKey(&k);
    string chkAddr = secp->GetAddress(searchType, mode, p);
    if (chkAddr != addr) {
        k.Neg();
        k.Add(&secp->order);
        p = secp->ComputePublicKey(&k);
        chkAddr = secp->GetAddress(searchType, mode, p);
        if (chkAddr != addr) {
            printf("\nWarning, wrong private key generated !\n");
            printf("  Addr :%s\n", addr.c_str());
            printf("  Check:%s\n", chkAddr.c_str());
        }
    }

    output(addr, secp->GetPrivAddress(mode, k), k.GetBase16());
    return true;
}

void KeyHunt::output(string addr, string pAddr, string pAddrHex)
{
#ifdef WIN64
    WaitForSingleObject(ghMutex, INFINITE);
#else
    pthread_mutex_lock(&ghMutex);
#endif

    FILE* f = stdout;
    bool needToClose = false;

    if (outputFile.length() > 0) {
        f = fopen(outputFile.c_str(), "a");
        if (f == NULL) {
            printf("Cannot open %s for writing\n", outputFile.c_str());
            f = stdout;
        } else {
            needToClose = true;
        }
    }

    if (!needToClose)
        printf("\n");

    fprintf(f, "PubAddress: %s\n", addr.c_str());
    fprintf(stdout, "\n==================================================================\n");
    fprintf(stdout, "PubAddress: %s\n", addr.c_str());

    switch (searchType) {
        case P2PKH:
            fprintf(f, "Priv (WIF): p2pkh:%s\n", pAddr.c_str());
            fprintf(stdout, "Priv (WIF): p2pkh:%s\n", pAddr.c_str());
            break;
        case P2SH:
            fprintf(f, "Priv (WIF): p2wpkh-p2sh:%s\n", pAddr.c_str());
            fprintf(stdout, "Priv (WIF): p2wpkh-p2sh:%s\n", pAddr.c_str());
            break;
        case BECH32:
            fprintf(f, "Priv (WIF): p2wpkh:%s\n", pAddr.c_str());
            fprintf(stdout, "Priv (WIF): p2wpkh:%s\n", pAddr.c_str());
            break;
    }
    fprintf(f, "Priv (HEX): 0x%s\n", pAddrHex.c_str());
    fprintf(stdout, "Priv (HEX): 0x%s\n", pAddrHex.c_str());

    fprintf(f, "==================================================================\n");
    fprintf(stdout, "==================================================================\n");

    if (needToClose)
        fclose(f);

#ifdef WIN64
    ReleaseMutex(ghMutex);
#else
    pthread_mutex_unlock(&ghMutex);
#endif
}

bool KeyHunt::isAlive(TH_PARAM * p)
{
    bool isAlive = true;
    int total = nbCPUThread + nbGPUThread;
    for (int i = 0; i < total; i++)
        isAlive = isAlive && p[i].isRunning;

    return isAlive;
}

bool KeyHunt::hasStarted(TH_PARAM * p)
{
    bool hasStarted = true;
    int total = nbCPUThread + nbGPUThread;
    for (int i = 0; i < total; i++)
        hasStarted = hasStarted && p[i].hasStarted;

    return hasStarted;
}

uint64_t KeyHunt::getGPUCount()
{
    uint64_t count = 0;
    for (int i = 0; i < nbGPUThread; i++)
        count += counters[0x80L + i];
    return count;
}

uint64_t KeyHunt::getCPUCount()
{
    uint64_t count = 0;
    for (int i = 0; i < nbCPUThread; i++)
        count += counters[i];
    return count;
}

int KeyHunt::CheckBloomBinary(const uint8_t * hash)
{
    if (bloom->check(hash, 20) > 0) {
        uint8_t* temp_read;
        uint64_t half, min, max, current;
        int64_t rcmp;
        int32_t r = 0;
        min = 0;
        current = 0;
        max = TOTAL_ADDR;
        half = TOTAL_ADDR;
        while (!r && half >= 1) {
            half = (max - min) / 2;
            temp_read = DATA + ((current + half) * 20);
            rcmp = memcmp(hash, temp_read, 20);
            if (rcmp == 0) {
                r = 1;
            } else {
                if (rcmp < 0) {
                    max = (max - half);
                } else {
                    min = (min + half);
                }
                current = min;
            }
        }
        return r;
    }
    return 0;
}

bool KeyHunt::MatchHash160(uint32_t * _h)
{
    if (_h[0] == hash160[0] &&
        _h[1] == hash160[1] &&
        _h[2] == hash160[2] &&
        _h[3] == hash160[3] &&
        _h[4] == hash160[4]) {
        return true;
    }
    return false;
}

std::string KeyHunt::formatThousands(uint64_t x)
{
    char buf[32] = "";
    sprintf(buf, "%lu", x); 
    std::string s(buf);
    int len = (int)s.length();
    int numCommas = (len - 1) / 3;

    if (numCommas == 0) {
        return s;
    }

    std::string result = "";
    int count = ((len % 3) == 0) ? 0 : (3 - (len % 3));

    for (int i = 0; i < len; i++) {
        result += s[i];
        if (count++ == 2 && i < len - 1) {
            result += ",";
            count = 0;
        }
    }
    return result;
}

char* KeyHunt::toTimeStr(int sec, char* timeStr)
{
    int h, m, s;
    h = (sec / 3600);
    m = (sec - (3600 * h)) / 60;
    s = (sec - (3600 * h) - (m * 60));
    sprintf(timeStr, "%0*d:%0*d:%0*d", 2, h, 2, m, 2, s);
    return (char*)timeStr;
}
