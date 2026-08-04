#include "pisat/pisat.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << '\n';
        std::exit(1);
    }
}

} // namespace

int main() {
    const std::string csv =
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
        "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "AA:BB:CC:DD:EE:FF, 2026-01-01 10:00:00, 2026-01-01 10:00:02, 6, 54, WPA2, "
        "CCMP, PSK, -42, 10, 3, 0.0.0.0, 7, TestNet,\n"
        "\n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, "
        "Probed ESSIDs\n"
        "11:22:33:44:55:66, 2026-01-01 10:00:01, 2026-01-01 10:00:03, -55, 7, "
        "AA:BB:CC:DD:EE:FF, TestNet\n";

    const auto devices = pisat::parse_airodump_csv(csv);
    require(devices.size() == 2, "parser returns AP and station");
    require(devices[0].kind == "access_point", "first device is AP");
    require(devices[0].essid == "TestNet", "AP ESSID parsed");
    require(devices[1].kind == "station", "second device is station");
    require(devices[1].bssid == "AA:BB:CC:DD:EE:FF", "station BSSID parsed");
    require(pisat::valid_interface_name("wlan1"), "valid Linux interface accepted");
    require(!pisat::valid_interface_name("wlan1;reboot"), "shell metacharacters rejected");
    require(pisat::parse_capture_engine("wireshark") ==
                pisat::CaptureEngine::wireshark, "Wireshark maps to dumpcap engine");
    require(pisat::json_boolean(R"({"enabled":true})", "enabled") == true,
            "JSON boolean parsed");
    require(pisat::json_integer(R"({"channel":11})", "channel") == 11,
            "JSON integer parsed");
    require(!pisat::json_integer(R"({"channel":99999999999999999999})", "channel"),
            "oversized JSON integer rejected");
    std::string frame_error;
    const auto secure_frame = pisat::make_secure_lora_frame(
        "pitak-a", "pisat", 100, "STATUS", "", "test-secret-key-123");
    std::map<std::string, std::uint64_t> secure_nonces;
    const auto secure_request = pisat::parse_secure_lora_frame(
        secure_frame, "pisat", "test-secret-key-123", secure_nonces, frame_error);
    require(secure_request && secure_request->source == "pitak-a" &&
                secure_request->target == "pisat" &&
                secure_request->command == "STATUS",
            "AES-GCM LoRa frame authenticates and decrypts");
    require(!pisat::parse_secure_lora_frame(
                secure_frame, "pisat", "test-secret-key-123",
                secure_nonces, frame_error),
            "secure LoRa replay rejected per sender");
    auto secure_tampered = secure_frame;
    secure_tampered.back() = secure_tampered.back() == 'A' ? 'B' : 'A';
    secure_nonces.clear();
    require(!pisat::parse_secure_lora_frame(
                secure_tampered, "pisat", "test-secret-key-123",
                secure_nonces, frame_error),
            "AES-GCM LoRa tampering rejected");
    require(pisat::make_secure_lora_frame(
                "pitak", "pisat", 42, "STATUS", "", "shared secret") ==
                "P2|pitak|pisat|42|STATUS||XNF8E2Iu6lIi/3AD5cUEjQ==",
            "PiSAT and PiTak share the same AES-GCM protocol vector");
    const auto page = pisat::devices_to_lora_page(devices, 0, 2);
    require(page.find("AA:BB:CC:DD:EE:FF") != std::string::npos,
            "LoRa device page contains compact device data");
    auto long_name_devices = devices;
    long_name_devices[0].essid = std::string(32, '|');
    require(pisat::devices_to_lora_page(long_name_devices, 0, 2).size() < 160,
            "LoRa device pages remain bounded with escaped ESSIDs");
    require(pisat::sx126x_mode_levels("normal") == std::pair<int, int>{0, 0},
            "SX126x normal mode drives M0 and M1 low");
    require(pisat::sx126x_mode_levels("configuration") == std::pair<int, int>{1, 1},
            "SX126x configuration mode drives M0 and M1 high");
    std::cout << "PiSAT tests passed\n";
}
