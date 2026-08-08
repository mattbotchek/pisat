#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

class SX126X;

namespace pisat {

struct Config {
    std::string interface = "wlan1";
    std::string bind_address = "127.0.0.1";
    std::uint16_t port = 8080;
    bool http_enabled = false;
    std::string api_token;
    bool lora_enabled = true;
    std::string lora_device = "/dev/serial0";
    int lora_baud = 9600;
    std::string lora_node_id = "replace-with-unique-node-id";
    std::string lora_key;
    std::vector<std::string> lora_allowed_controllers;
    int lora_m0_gpio = 22;
    int lora_m1_gpio = 27;
    int lora_aux_gpio = 17;
    bool lora_aux_active_high = true;
    int lora_aux_timeout_ms = 2000;
    int lora_publish_interval_seconds = 30;
    int lora_max_frame_bytes = 220;
    std::string data_directory = "/var/lib/pisat";
    std::string default_engine = "tcpdump";
    int default_channel = 0;
    int device_ttl_seconds = 300;

    static Config load(const std::string& path);
};

struct CommandResult {
    int exit_code = -1;
    std::string output;
};

class Process {
public:
    Process() = default;
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    Process(Process&& other) noexcept;
    Process& operator=(Process&& other) noexcept;
    ~Process();

    bool start(const std::vector<std::string>& args,
               const std::optional<std::string>& output_file = std::nullopt);
    void stop(std::chrono::milliseconds grace = std::chrono::seconds(3));
    bool running() const;
    long id() const;

private:
    mutable long pid_ = -1;
};

CommandResult run_command(const std::vector<std::string>& args);
bool valid_interface_name(const std::string& value);

class MonitorController {
public:
    explicit MonitorController(std::string interface);
    CommandResult set_enabled(bool enabled, int channel = 0) const;
    bool is_monitor_mode() const;

private:
    std::string interface_;
};

enum class CaptureEngine { tcpdump, airodump, wireshark };

std::optional<CaptureEngine> parse_capture_engine(const std::string& value);
std::string capture_engine_name(CaptureEngine engine);

struct CaptureStatus {
    bool active = false;
    std::string engine;
    std::string output;
    long pid = -1;
    std::string error;
};

class CaptureManager {
public:
    explicit CaptureManager(std::string interface);
    ~CaptureManager();

    bool start(CaptureEngine engine, const std::string& output, std::string& error);
    void stop();
    CaptureStatus status() const;

private:
    std::string interface_;
    mutable std::mutex mutex_;
    Process process_;
    CaptureStatus status_;
};

struct WirelessDevice {
    std::string mac;
    std::string kind;
    std::string first_seen;
    std::string last_seen;
    std::string channel;
    std::string signal_dbm;
    std::string packets;
    std::string bssid;
    std::string essid;
    std::string manufacturer;
};

std::vector<WirelessDevice> parse_airodump_csv(const std::string& text);
std::string devices_to_json(const std::vector<WirelessDevice>& devices);
std::string devices_to_lora_page(const std::vector<WirelessDevice>& devices,
                                 std::size_t offset, std::size_t limit);

class DeviceTracker {
public:
    DeviceTracker(std::string interface, std::string data_directory, int ttl_seconds);
    ~DeviceTracker();

    bool start(std::string& error);
    void stop();
    std::vector<WirelessDevice> snapshot() const;
    std::string csv_path() const;

private:
    void refresh_loop();

    std::string interface_;
    std::string data_directory_;
    std::string prefix_;
    int ttl_seconds_;
    mutable std::mutex mutex_;
    std::map<std::string, WirelessDevice> devices_;
    std::map<std::string, std::chrono::steady_clock::time_point> last_observed_;
    Process survey_;
    std::atomic<bool> stop_requested_{false};
    std::thread refresh_thread_;
};

struct HttpRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct HttpResponse {
    int status = 200;
    std::string content_type = "application/json";
    std::string body = "{}";
};

class HttpServer {
public:
    using Handler = std::function<HttpResponse(const HttpRequest&)>;

    HttpServer(std::string address, std::uint16_t port, Handler handler);
    ~HttpServer();
    bool run(std::string& error);
    void stop();

private:
    std::string address_;
    std::uint16_t port_;
    Handler handler_;
    std::atomic<bool> stop_requested_{false};
    long socket_ = -1;
};

struct LoRaRequest {
    std::uint64_t nonce = 0;
    std::string source;
    std::string target;
    std::string command;
    std::string arguments;
};

std::string make_secure_lora_frame(const std::string& source, const std::string& target,
                                   std::uint64_t nonce, const std::string& type,
                                   const std::string& payload, const std::string& key);
std::optional<LoRaRequest> parse_secure_lora_frame(
    const std::string& frame, const std::string& node_id, const std::string& key,
    std::map<std::string, std::uint64_t>& last_nonces, std::string& error);
std::pair<int, int> sx126x_mode_levels(const std::string& mode);

class LoRaServer {
public:
    using Handler = std::function<std::pair<std::string, std::string>(const LoRaRequest&)>;
    using Publisher = std::function<std::string()>;

    LoRaServer(std::string device, int baud, std::string node_id, std::string key,
               std::string nonce_file,
               int m0_gpio, int m1_gpio, int aux_gpio, bool aux_active_high,
               int aux_timeout_ms,
               int max_frame_bytes, int publish_interval_seconds,
               Handler handler, Publisher publisher);
    ~LoRaServer();
    bool run(std::string& error);
    void stop();

private:
    bool write_frame(const std::string& frame);
    std::uint64_t next_outbound_nonce();
    bool initialize_hat(std::string& error);
    bool wait_hat_ready(std::string& error) const;
    void shutdown_hat();

    std::string device_;
    int baud_;
    std::string node_id_;
    std::string key_;
    std::string nonce_file_;
    int m0_gpio_;
    int m1_gpio_;
    int aux_gpio_;
    bool aux_active_high_;
    int aux_timeout_ms_;
    int max_frame_bytes_;
    int publish_interval_seconds_;
    Handler handler_;
    Publisher publisher_;
    std::atomic<bool> stop_requested_{false};
    std::unique_ptr<::SX126X> sx126x_;
    std::map<std::string, std::uint64_t> last_nonces_;
    std::uint64_t outbound_nonce_ = 0;
};

std::string json_escape(const std::string& value);
std::optional<bool> json_boolean(const std::string& body, const std::string& key);
std::optional<int> json_integer(const std::string& body, const std::string& key);
std::optional<std::string> json_string(const std::string& body, const std::string& key);

} // namespace pisat
