#include "Timer.h"
#include "KeyHunt.h"
#include "Base58.h"
#include "ArgParse.h"
#include <fstream>
#include <vector>
#include <string>
#include <bitset>
#include <sstream>
#include <stdexcept>
#include <cassert>
#ifndef WIN64
#include <signal.h>
#include <unistd.h>
#endif
#include <gmp.h>
#include <chrono>
#include <cstdlib>
#include <iomanip>

#define RELEASE "1.00"

using namespace std;
using namespace argparse;
bool should_exit = false;

// Fungsi untuk membaca file dan menyimpan setiap baris sebagai nilai hex
std::vector<std::string> readHexValuesFromFile(const std::string& filePath) {
    std::ifstream infile(filePath);
    std::vector<std::string> values;
    std::string line;

    while (std::getline(infile, line)) {
        // Mengabaikan baris kosong
        if (!line.empty()) {
            values.push_back(line);
        }
    }

    return values;
}

// Fungsi untuk mengonversi integer ke string biner dengan panjang bit tertentu
std::string intToBinary(int num, int bitLength) {
    std::bitset<64> bin(num);
    return bin.to_string().substr(64 - bitLength);
}

// Fungsi konversi dari biner ke heksadesimal
std::string binaryToHex(const std::string &binaryStr) {
    mpz_t num;
    mpz_init(num);
    mpz_set_str(num, binaryStr.c_str(), 2);  // Set num to the value of binaryStr interpreted as a binary number
    char* hex_cstr = mpz_get_str(NULL, 16, num);  // Convert num to a hexadecimal string
    std::string hex_str(hex_cstr);
    free(hex_cstr);
    mpz_clear(num);
    return hex_str;
}

// Fungsi untuk menghasilkan rentang nilai biner
std::vector<std::pair<std::string, std::string>> generateBinaryRanges(int bitLength, int numPatterns) {
    std::vector<std::string> binaryRange;
    int maxValue = (1 << bitLength) - 1; // 2^bitLength - 1

    for (int i = 0; i <= maxValue; ++i) {
        std::string binaryStr = intToBinary(i, bitLength);
        binaryRange.push_back(binaryStr);
    }

    std::vector<std::pair<std::string, std::string>> combinedRanges;
    mpz_t totalCombinations;
    mpz_init(totalCombinations);
    mpz_ui_pow_ui(totalCombinations, binaryRange.size(), numPatterns);  // binaryRange.size() ^ numPatterns

    mpz_t i;
    mpz_init_set_ui(i, 0);
    while (mpz_cmp(i, totalCombinations) < 0) {
        std::string combined;
        unsigned long combination = mpz_get_ui(i);
        for (int j = 0; j < numPatterns; ++j) {
            int index = combination % binaryRange.size();
            combined += binaryRange[index];
            combination /= binaryRange.size();
        }
        std::string hexValue = binaryToHex(combined);
        combinedRanges.emplace_back(binaryRange.front(), binaryRange.back());
        mpz_add_ui(i, i, 1);
    }

    mpz_clear(totalCombinations);
    mpz_clear(i);
    return combinedRanges;
}

// ----------------------------------------------------------------------------

void getInts(string name, vector<int>& tokens, const string& text, char sep) {
    size_t start = 0, end = 0;
    tokens.clear();
    int item;

    try {
        while ((end = text.find(sep, start)) != string::npos) {
            item = std::stoi(text.substr(start, end - start));
            tokens.push_back(item);
            start = end + 1;
        }
        item = std::stoi(text.substr(start));
        tokens.push_back(item);
    } catch (std::invalid_argument&) {
        printf("Invalid %s argument, number expected\n", name.c_str());
        exit(-1);
    }
}

#ifdef WIN64
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    switch (fdwCtrlType) {
    case CTRL_C_EVENT:
        should_exit = true;
        return TRUE;
    default:
        return TRUE;
    }
}
#else
void CtrlHandler(int signum) {
    printf("\n\nBYE\n");
    exit(signum);
}
#endif

int main(int argc, const char* argv[]) {
    // Global Init
    Timer::Init();
    rseed(Timer::getSeed32());

    bool gpuEnable = false;
    bool gpuAutoGrid = true;
    int searchMode = SEARCH_COMPRESSED;
    vector<int> gpuId = { 0 };
    vector<int> gridSize;
    string outputFile = "Found.txt";
    string hash160File = "";
    string address = "";
    std::vector<unsigned char> hash160;
    bool singleAddress = false;
    int nbCPUThread = Timer::getCoreNumber();
    bool tSpecified = false;
    bool sse = true;
    uint32_t maxFound = 1024 * 64;
    string rangeStart = "";
    string rangeEnd = "";
    hash160.clear();

    ArgumentParser parser("KeyHunt-Cuda-2", "Hunt for Bitcoin private keys.");

    parser.add_argument("-v", "--version", "Print version", false);
    parser.add_argument("-c", "--check", "Check the working of the codes", false);
    parser.add_argument("-u", "--uncomp", "Search uncompressed addresses", false);
    parser.add_argument("-b", "--both", "Search both uncompressed or compressed addresses", false);
    parser.add_argument("-g", "--gpu", "Enable GPU calculation", false);
    parser.add_argument("-i", "--gpui", "GPU ids: 0,1...: List of GPU(s) to use, default is 0", false);
    parser.add_argument("-x", "--gpux", "GPU gridsize: g0x,g0y,g1x,g1y, ...: Specify GPU(s) kernel gridsize, default is 8*(Device MP count),128", false);
    parser.add_argument("-o", "--out", "Outputfile: Output results to the specified file, default: Found.txt", false);
    parser.add_argument("-m", "--max", "Specify maximun number of addresses found by each kernel call", false);
    parser.add_argument("-t", "--thread", "threadNumber: Specify number of CPU thread, default is number of core", false);
    parser.add_argument("-l", "--list", "List cuda enabled devices", false);
    parser.add_argument("-f", "--file", "Ripemd160 binary hash file path", false);
    parser.add_argument("-a", "--addr", "P2PKH Address (single address mode)", false);
    parser.add_argument("--hexfile", "Input file containing hex values", false); // Argumen untuk hexfile
    parser.add_argument("--bit", "Length of binary pattern", false); // Argumen untuk panjang pattern biner
    parser.add_argument("-n","--num-patterns", "Number of binary patterns to combine", false); // Argumen untuk jumlah pola biner

    parser.enable_help();

    auto err = parser.parse(argc, argv);
    if (err) {
        std::cout << err << std::endl;
        parser.print_help();
        return -1;
    }

    if (parser.exists("help")) {
        parser.print_help();
        return 0;
    }

    if (parser.exists("version")) {
        printf("KeyHunt-Cuda-2 v" RELEASE "\n");
        return 0;
    }

    if (parser.exists("check")) {
        printf("KeyHunt-Cuda-2 v" RELEASE "\n\n");

        printf("\nChecking... Secp256K1\n\n");
        Secp256K1 sec;
        sec.Init();
        sec.Check();

        printf("\n\nChecking... Int\n\n");
        Int K;
        K.SetBase16("3EF7CEF65557B61DC4FF2313D0049C584017659A32B002C105D04A19DA52CB47");
        K.Check();

        printf("\n\nCheck completed successfully\n\n");
        return 0;
    }

    if (parser.exists("uncomp")) {
        searchMode = SEARCH_UNCOMPRESSED;
    }
    if (parser.exists("both")) {
        searchMode = SEARCH_BOTH;
    }

    if (parser.exists("gpu")) {
        gpuEnable = true;
        nbCPUThread = 0;
    }

    if (parser.exists("gpui")) {
        string ids = parser.get<string>("i");
        getInts("gpui", gpuId, ids, ',');
    }

    if (parser.exists("gpux")) {
        string grids = parser.get<string>("x");
        getInts("gpux", gridSize, grids, ',');
        gpuAutoGrid = false;
    }

    if (parser.exists("out")) {
        outputFile = parser.get<string>("o");
    }

    if (parser.exists("max")) {
        maxFound = parser.get<uint32_t>("m");
    }

    if (parser.exists("thread")) {
        nbCPUThread = parser.get<int>("t");
        tSpecified = true;
    }

    if (parser.exists("list")) {
#ifdef WIN64
        GPUEngine::PrintCudaInfo();
#else
        printf("GPU code not compiled, use -DWITHGPU when compiling.\n");
#endif
        return 0;
    }

    if (parser.exists("file")) {
        hash160File = parser.get<string>("f");
    }

    if (parser.exists("addr")) {
        address = parser.get<string>("a");
        if (address.length() < 30 || address[0] != '1') {
            printf("Invalid addr argument, must have P2PKH address only\n");
            exit(-1);
        } else {
            if (DecodeBase58(address, hash160)) {
                hash160.erase(hash160.begin() + 0);
                hash160.erase(hash160.begin() + 20, hash160.begin() + 24);
                assert(hash160.size() == 20);
            }
        }
    }

    std::string inputFile = parser.get<std::string>("hexfile"); // Mendapatkan argumen hexfile
    int bitLength = parser.exists("bit") ? std::stoi(parser.get<std::string>("bit")) : 0; // Mendapatkan panjang pattern biner
    int numPatterns = parser.exists("num-patterns") ? std::stoi(parser.get<std::string>("num-patterns")) : 0; // Mendapatkan jumlah pola biner

    if (!inputFile.empty() || (bitLength > 0 && numPatterns > 0)) {
        std::vector<std::pair<std::string, std::string>> binaryRanges;

        if (!inputFile.empty()) {
            auto hexValues = readHexValuesFromFile(inputFile);
            for (const auto& hex : hexValues) {
                // Mengonversi setiap nilai hex ke biner dan menambahkannya ke rentang biner
                mpz_t num;
                mpz_init_set_str(num, hex.c_str(), 16);
                char* bin_cstr = mpz_get_str(NULL, 2, num);
                binaryRanges.emplace_back(std::string(bin_cstr), hex);
                free(bin_cstr);
                mpz_clear(num);
            }
        } else if (bitLength > 0 && numPatterns > 0) {
            binaryRanges = generateBinaryRanges(bitLength, numPatterns);
        }

        std::cout << "Total binary values generated: " << binaryRanges.size() << std::endl;

        for (const auto& range : binaryRanges) {
            const auto& binStart = range.first;
            const auto& binEnd = range.second;

            // Debug print untuk memeriksa nilai biner yang dihasilkan
            std::cout << "Processing binary range: " << binStart << " to " << binEnd << std::endl;

            // Mengonversi nilai biner ke hex
            std::string hexStart = binaryToHex(binStart);
            std::string hexEnd = binaryToHex(binEnd);

            std::cout << "Converted hex range: " << hexStart << " to " << hexEnd << std::endl;

            Int startRange, endRange;
            try {
                startRange.SetBase16(hexStart.c_str());
                endRange.SetBase16(hexEnd.c_str());
            } catch (const std::invalid_argument& e) {
                std::cerr << "Error: Invalid hex value: " << hexStart << " or " << hexEnd << std::endl;
                continue;
            }

            // Debug print untuk memeriksa nilai range yang dihasilkan
            std::cout << "Start range: " << startRange.GetBase16() << std::endl;
            std::cout << "End range: " << endRange.GetBase16() << std::endl;

            // Menggunakan KeyHunt untuk memproses rentang ini
            try {
                KeyHunt keyhunt(hash160File, hash160, searchMode, gpuEnable,
                    outputFile, sse, maxFound, startRange.GetBase16(), endRange.GetBase16(), should_exit);
                keyhunt.Search(nbCPUThread, gpuId, gridSize, should_exit);
            } catch (const std::exception& e) {
                std::cerr << "Error processing binary range " << binStart << " to " << binEnd << ": " << e.what() << std::endl;
                continue;
            }
        }
    } else {
        if (gridSize.size() == 0) {
            for (int i = 0; i < gpuId.size(); i++) {
                gridSize.push_back(-1);
                gridSize.push_back(128);
            }
        } else if (gridSize.size() != gpuId.size() * 2) {
            printf("Invalid gridSize or gpuId argument, must have coherent size\n");
            exit(-1);
        }

        if ((hash160.size() <= 0) && (hash160File.length() <= 0)) {
            printf("Invalid ripemd160 binary hash file path or invalid address\n");
            exit(-1);
        }

        if ((hash160.size() > 0) && (hash160File.length() > 0)) {
            printf("Invalid arguments, addr and file, both option can't be used together\n");
            exit(-1);
        }

        if (rangeStart.length() <= 0) {
            printf("Invalid rangeStart argument, please provide start range at least, endRange would be: startRange + 10000000000000000\n");
            exit(-1);
        }

        if (nbCPUThread > 0 && gpuEnable) {
            printf("Invalid arguments, CPU and GPU, both can't be used together right now\n");
            exit(-1);
        }

        if (!tSpecified && nbCPUThread > 1 && gpuEnable)
            nbCPUThread -= (int)gpuId.size();
        if (nbCPUThread < 0)
            nbCPUThread = 0;

        {
            printf("\n");
            printf("KeyHunt-Cuda-2 v" RELEASE "\n");
            printf("\n");
            printf("MODE         : %s\n", searchMode == SEARCH_COMPRESSED ? "COMPRESSED" : (searchMode == SEARCH_UNCOMPRESSED ? "UNCOMPRESSED" : "COMPRESSED & UNCOMPRESSED"));
            printf("DEVICE       : %s\n", (gpuEnable && nbCPUThread > 0) ? "CPU & GPU" : ((!gpuEnable && nbCPUThread > 0) ? "CPU" : "GPU"));
            printf("CPU THREAD   : %d\n", nbCPUThread);
            printf("GPU IDS      : ");
            for (int i = 0; i < gpuId.size(); i++) {
                printf("%d", gpuId.at(i));
                if (i + 1 < gpuId.size())
                    printf(", ");
            }
            printf("\n");
            printf("GPU GRIDSIZE : ");
            for (int i = 0; i < gridSize.size(); i++) {
                printf("%d", gridSize.at(i));
                if (i + 1 < gridSize.size()) {
                    if ((i + 1) % 2 != 0) {
                        printf("x");
                    } else {
                        printf(", ");
                    }
                }
            }
            if (gpuAutoGrid)
                printf(" (grid size will be calculated automatically based on multiprocessor number on GPU device)\n");
            else
                printf("\n");
            printf("SSE          : %s\n", sse ? "YES" : "NO");
            printf("MAX FOUND    : %d\n", maxFound);
            if (hash160File.length() > 0)
                printf("HASH160 FILE : %s\n", hash160File.c_str());
            else
                printf("ADDRESS      : %s (single address mode)\n", address.c_str());
            printf("OUTPUT FILE  : %s\n", outputFile.c_str());
        }
#ifdef WIN64
        if (SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
            KeyHunt* v = new KeyHunt(hash160File, hash160, searchMode, gpuEnable,
                outputFile, sse, maxFound, rangeStart, rangeEnd, should_exit);

            v->Search(nbCPUThread, gpuId, gridSize, should_exit);

            delete v;
            printf("\n\nBYE\n");
            return 0;
        } else {
            printf("error: could not set control-c handler\n");
            return 1;
        }
#else
        signal(SIGINT, CtrlHandler);
        KeyHunt* v = new KeyHunt(hash160File, hash160, searchMode, gpuEnable,
            outputFile, sse, maxFound, rangeStart, rangeEnd, should_exit);

        v->Search(nbCPUThread, gpuId, gridSize, should_exit);

        delete v;
        return 0;
#endif
    }
}
