#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <vector>

int main(int argc, char* argv[]) {
    std::string targetMac = "";
    std::string csvFile = "";
    int minPwr = -999;
    bool showBssid = false;
    bool showRate = false;
    bool showProbes = false;

    // Parse args
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--mac" && i+1 < argc) targetMac = argv[++i];
        else if (arg == "--csv" && i+1 < argc) csvFile = argv[++i];
        else if (arg == "--min-pwr" && i+1 < argc) minPwr = std::stoi(argv[++i]);
        else if (arg == "--show-bssid") showBssid = true;
        else if (arg == "--show-rate") showRate = true;
        else if (arg == "--show-probes") showProbes = true;
    }

    if (targetMac.empty() || csvFile.empty()) {
        std::cerr << "Usage: track_device --mac <MAC> --csv <FILE> [--min-pwr N] [--show-bssid] [--show-rate] [--show-probes]\n";
        return 1;
    }

    std::transform(targetMac.begin(), targetMac.end(), targetMac.begin(), ::toupper);

    std::ifstream in(csvFile);
    if (!in) {
        std::cerr << "Cannot open CSV: " << csvFile << "\n";
        return 1;
    }

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;

        std::stringstream ss(line);
        std::vector<std::string> cols;
        std::string field;

        while (std::getline(ss, field, ',')) {
            field.erase(0, field.find_first_not_of(" \t"));
            field.erase(field.find_last_not_of(" \t") + 1);
            cols.push_back(field);
        }

        if (cols.size() < 6) continue;

        std::string station = cols[1];
        std::transform(station.begin(), station.end(), station.begin(), ::toupper);

        if (station == targetMac) {
            int pwr = std::stoi(cols[2]);
            if (pwr < minPwr) continue;

            std::cout << "MAC=" << station
                      << " PWR=" << pwr
                      << " Frames=" << cols[5];

            if (showBssid) std::cout << " BSSID=" << cols[0];
            if (showRate)  std::cout << " Rate="  << cols[3];
            if (showProbes && cols.size() > 6) std::cout << " Probes=" << cols.back();

            std::cout << "\n";
        }
    }

    return 0;
}
