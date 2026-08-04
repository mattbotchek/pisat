#include "pisat/pisat.hpp"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>

namespace {

std::atomic<bool> interrupted = false;

void handle_signal(int) {
    interrupted = true;
}

void usage() {
    std::cout <<
        "PiSAT passive wireless monitoring\n\n"
        "Usage:\n"
        "  pisat [--config FILE] serve\n"
        "  pisat [--config FILE] monitor on [--channel N]\n"
        "  pisat [--config FILE] monitor off\n"
        "  pisat [--config FILE] monitor status\n"
        "  pisat [--config FILE] lora-frame --target NODE --nonce N --command CMD [--args VALUE]\n"
        "  pisat [--config FILE] capture --engine tcpdump|airodump|wireshark --output FILE\n\n"
        "Capture runs until SIGINT/SIGTERM. The wireshark engine uses dumpcap and writes pcapng.\n";
}

std::string option_value(int argc, char** argv, const std::string& name,
                         const std::string& fallback = {}) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (argv[i] == name) return argv[i + 1];
    }
    return fallback;
}

bool authorized(const pisat::HttpRequest& request, const std::string& token) {
    if (token.empty()) return true;
    const auto it = request.headers.find("authorization");
    if (it == request.headers.end()) return false;
    const std::string expected = "Bearer " + token;
    if (it->second.size() != expected.size()) return false;
    unsigned char difference = 0;
    for (std::size_t i = 0; i < expected.size(); ++i)
        difference |= static_cast<unsigned char>(it->second[i] ^ expected[i]);
    return difference == 0;
}

std::optional<int> parse_integer(const std::string& value) {
    int parsed = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size()) return std::nullopt;
    return parsed;
}

std::optional<std::uint64_t> parse_nonce(const std::string& value) {
    std::uint64_t parsed = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size()) return std::nullopt;
    return parsed;
}

std::vector<std::string> split_arguments(const std::string& value) {
    std::vector<std::string> result;
    std::size_t start = 0;
    while (true) {
        const auto end = value.find(',', start);
        result.push_back(value.substr(start, end == std::string::npos ? end : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result;
}

} // namespace

int main(int argc, char** argv) {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    if (argc < 2) {
        usage();
        return 2;
    }

    const auto config_path = option_value(argc, argv, "--config", "/etc/pisat/pisat.conf");
    pisat::Config config;
    try {
        config = pisat::Config::load(config_path);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }

    int command_index = 1;
    if (std::string(argv[1]) == "--config") command_index = 3;
    if (command_index >= argc) {
        usage();
        return 2;
    }
    const std::string command = argv[command_index];
    pisat::MonitorController monitor(config.interface);

    if (command == "monitor") {
        if (command_index + 1 >= argc) {
            usage();
            return 2;
        }
        const std::string action = argv[command_index + 1];
        if (action == "status") {
            std::cout << (monitor.is_monitor_mode() ? "monitor\n" : "managed\n");
            return 0;
        }
        if (action != "on" && action != "off") {
            usage();
            return 2;
        }
        const auto channel = parse_integer(option_value(
            argc, argv, "--channel", std::to_string(config.default_channel)));
        if (!channel) {
            std::cerr << "channel must be an integer\n";
            return 2;
        }
        const auto result = monitor.set_enabled(action == "on", *channel);
        if (result.exit_code != 0) {
            std::cerr << result.output << '\n';
            return 1;
        }
        std::cout << config.interface << " set to " << (action == "on" ? "monitor" : "managed")
                  << " mode\n";
        return 0;
    }

    if (command == "capture") {
        const auto engine_name = option_value(argc, argv, "--engine", config.default_engine);
        const auto engine = pisat::parse_capture_engine(engine_name);
        const auto output = option_value(argc, argv, "--output");
        if (!engine || output.empty()) {
            usage();
            return 2;
        }
        pisat::CaptureManager capture(config.interface);
        std::string error;
        if (!capture.start(*engine, output, error)) {
            std::cerr << error << '\n';
            return 1;
        }
        while (!interrupted) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        capture.stop();
        return 0;
    }

    if (command == "lora-frame") {
        const auto nonce = option_value(argc, argv, "--nonce");
        const auto parsed_nonce = nonce.empty() ? std::optional<std::uint64_t>{} :
                                  parse_nonce(nonce);
        const auto frame_command = option_value(argc, argv, "--command");
        const auto target = option_value(argc, argv, "--target", "pisat");
        if (!parsed_nonce || *parsed_nonce <= 0 || frame_command.empty() ||
            config.lora_key.empty()) {
            usage();
            return 2;
        }
        std::cout << pisat::make_secure_lora_frame(
            config.lora_node_id, target, *parsed_nonce, frame_command,
            option_value(argc, argv, "--args"), config.lora_key) << '\n';
        return 0;
    }

    if (command != "serve") {
        usage();
        return 2;
    }

    std::error_code ec;
    std::filesystem::create_directories(config.data_directory, ec);
    if (ec) {
        std::cerr << "cannot create data directory: " << ec.message() << '\n';
        return 1;
    }

    pisat::CaptureManager capture(config.interface);
    pisat::DeviceTracker tracker(config.interface, config.data_directory,
                                 config.device_ttl_seconds);
    std::mutex control_mutex;
    std::string tracker_error;
    if (monitor.is_monitor_mode() && !tracker.start(tracker_error))
        std::cerr << "warning: " << tracker_error << '\n';

    const auto set_monitor = [&](bool enabled, int channel)
        -> std::pair<std::string, std::string> {
        std::scoped_lock lock(control_mutex);
        if (!enabled) {
            capture.stop();
            tracker.stop();
        }
        const auto result = monitor.set_enabled(enabled, channel);
        if (result.exit_code != 0) return {"ERR", "MONITOR"};
        if (enabled) {
            std::string error;
            if (!tracker.start(error)) return {"ERR", "SURVEY"};
        }
        return {"OK", enabled ? "MONITOR,ON" : "MONITOR,OFF"};
    };

    const auto start_capture = [&](const std::string& engine_name)
        -> std::pair<std::string, std::string> {
        const auto engine = pisat::parse_capture_engine(engine_name);
        if (!engine) return {"ERR", "ENGINE"};
        const auto extension =
            *engine == pisat::CaptureEngine::wireshark ? ".pcapng" :
            *engine == pisat::CaptureEngine::tcpdump ? ".pcap" : "";
        const auto output = (std::filesystem::path(config.data_directory) /
            ("capture-" + std::to_string(std::time(nullptr)) + extension)).string();
        std::scoped_lock lock(control_mutex);
        std::string error;
        if (!capture.start(*engine, output, error)) return {"ERR", "CAPTURE"};
        return {"OK", "CAPTURE,STARTED," + pisat::capture_engine_name(*engine)};
    };

    const auto stop_capture = [&]() -> std::pair<std::string, std::string> {
        std::scoped_lock lock(control_mutex);
        capture.stop();
        return {"OK", "CAPTURE,STOPPED"};
    };

    const auto compact_status = [&]() {
        const auto state = capture.status();
        return std::string("M,") + (monitor.is_monitor_mode() ? "1" : "0") +
               ",C," + (state.active ? "1" : "0") +
               ",E," + (state.engine.empty() ? "-" : state.engine) +
               ",D," + std::to_string(tracker.snapshot().size());
    };

    auto http_handler = [&](const pisat::HttpRequest& request) -> pisat::HttpResponse {
            if (request.path.starts_with("/api/") &&
                !authorized(request, config.api_token))
                return {401, "application/json", "{\"error\":\"unauthorized\"}"};

            if (request.method == "GET" && request.path == "/health")
                return {200, "application/json", "{\"status\":\"ok\"}"};

            if (request.method == "GET" && request.path == "/api/v1/devices")
                return {200, "application/json", pisat::devices_to_json(tracker.snapshot())};

            if (request.method == "GET" && request.path == "/api/v1/status") {
                const auto state = capture.status();
                std::ostringstream body;
                body << "{\"interface\":\"" << pisat::json_escape(config.interface)
                     << "\",\"monitor_mode\":" << (monitor.is_monitor_mode() ? "true" : "false")
                     << ",\"capture\":{\"active\":" << (state.active ? "true" : "false")
                     << ",\"engine\":\"" << pisat::json_escape(state.engine)
                     << "\",\"output\":\"" << pisat::json_escape(state.output)
                     << "\",\"pid\":" << state.pid << "},\"devices\":"
                     << tracker.snapshot().size() << "}";
                return {200, "application/json", body.str()};
            }

            if (request.method == "POST" && request.path == "/api/v1/monitor") {
                const auto enabled = pisat::json_boolean(request.body, "enabled");
                if (!enabled)
                    return {400, "application/json", "{\"error\":\"enabled is required\"}"};
                const int channel = pisat::json_integer(request.body, "channel").value_or(0);
                const auto result = set_monitor(*enabled, channel);
                if (result.first != "OK")
                    return {500, "application/json", "{\"error\":\"monitor change failed\"}"};
                return {200, "application/json",
                        std::string("{\"monitor_mode\":") + (*enabled ? "true}" : "false}")};
            }

            if (request.method == "POST" && request.path == "/api/v1/capture/start") {
                const auto engine_name =
                    pisat::json_string(request.body, "engine").value_or(config.default_engine);
                const auto engine = pisat::parse_capture_engine(engine_name);
                if (!engine)
                    return {400, "application/json", "{\"error\":\"unknown engine\"}"};
                auto output = pisat::json_string(request.body, "output");
                if (!output) {
                    const auto extension =
                        *engine == pisat::CaptureEngine::wireshark ? ".pcapng" :
                        *engine == pisat::CaptureEngine::tcpdump ? ".pcap" : "";
                    output = (std::filesystem::path(config.data_directory) /
                              ("capture-" + std::to_string(std::time(nullptr)) +
                               std::string(extension))).string();
                } else {
                    const auto base = std::filesystem::weakly_canonical(config.data_directory, ec);
                    const auto target = std::filesystem::weakly_canonical(*output, ec);
                    const auto relative = target.lexically_relative(base);
                    if (ec || relative.empty() || relative.is_absolute() ||
                        *relative.begin() == "..")
                        return {400, "application/json",
                                "{\"error\":\"output must be under data_directory\"}"};
                }
                std::scoped_lock lock(control_mutex);
                std::string error;
                if (!capture.start(*engine, *output, error))
                    return {409, "application/json",
                            "{\"error\":\"" + pisat::json_escape(error) + "\"}"};
                return {202, "application/json", "{\"capture\":\"started\"}"};
            }

            if (request.method == "POST" && request.path == "/api/v1/capture/stop") {
                stop_capture();
                return {200, "application/json", "{\"capture\":\"stopped\"}"};
            }

            return {404, "application/json", "{\"error\":\"not found\"}"};
        };

    auto lora_handler = [&](const pisat::LoRaRequest& request)
        -> std::pair<std::string, std::string> {
        if (request.command == "HEARTBEAT" || request.command == "MESSAGE" ||
            request.command == "EVENT")
            return {"", ""};
        if (std::find(config.lora_allowed_controllers.begin(),
                      config.lora_allowed_controllers.end(),
                      request.source) == config.lora_allowed_controllers.end())
            return {"", ""};
        if (request.command == "PING") return {"OK", "PONG"};
        if (request.command == "STATUS") return {"OK", compact_status()};
        if (request.command == "DEVICES") {
            const auto arguments = split_arguments(request.arguments);
            const auto offset = arguments.empty() || arguments[0].empty() ?
                                std::optional<int>(0) :
                                parse_integer(arguments[0]);
            const auto limit = arguments.size() < 2 || arguments[1].empty() ?
                               std::optional<int>(2) :
                               parse_integer(arguments[1]);
            if (!offset || !limit || *offset < 0 || *limit < 1)
                return {"ERR", "ARGS"};
            if (*limit > 1) return {"ERR", "LIMIT"};
            return {"OK", pisat::devices_to_lora_page(
                              tracker.snapshot(), static_cast<std::size_t>(*offset),
                              static_cast<std::size_t>(*limit))};
        }
        if (request.command == "MONITOR") {
            const auto arguments = split_arguments(request.arguments);
            if (arguments.empty()) return {"ERR", "ARGS"};
            if (arguments[0] == "OFF") return set_monitor(false, 0);
            if (arguments[0] != "ON") return {"ERR", "ARGS"};
            const auto channel = arguments.size() < 2 ? std::optional<int>(0) :
                                 parse_integer(arguments[1]);
            if (!channel) return {"ERR", "ARGS"};
            return set_monitor(true, *channel);
        }
        if (request.command == "CAPTURE") {
            const auto arguments = split_arguments(request.arguments);
            if (arguments.empty()) return {"ERR", "ARGS"};
            if (arguments[0] == "STOP") return stop_capture();
            if (arguments[0] == "START" && arguments.size() == 2)
                return start_capture(arguments[1]);
            return {"ERR", "ARGS"};
        }
        return {"ERR", "COMMAND"};
    };

    std::unique_ptr<pisat::HttpServer> http_server;
    if (config.http_enabled) {
        http_server = std::make_unique<pisat::HttpServer>(
            config.bind_address, config.port, http_handler);
    }
    std::unique_ptr<pisat::LoRaServer> lora_server;
    if (config.lora_enabled) {
        lora_server = std::make_unique<pisat::LoRaServer>(
            config.lora_device, config.lora_baud, config.lora_node_id, config.lora_key,
            (std::filesystem::path(config.data_directory) / "lora-nonce").string(),
            config.lora_m0_gpio, config.lora_m1_gpio, config.lora_aux_gpio,
            config.lora_aux_active_high, config.lora_aux_timeout_ms,
            config.lora_max_frame_bytes, config.lora_publish_interval_seconds,
            lora_handler, [&] { return compact_status(); });
    }

    if (config.lora_enabled)
        std::cout << "PiSAT LoRa service using " << config.lora_device << " at "
                  << config.lora_baud << " baud\n";
    if (config.http_enabled)
        std::cout << "PiSAT HTTP diagnostics listening on " << config.bind_address << ':'
                  << config.port << '\n';

    std::mutex error_mutex;
    std::string service_error;
    bool service_ok = true;
    std::thread http_thread;
    if (http_server && lora_server) {
        http_thread = std::thread([&] {
            std::string error;
            if (!http_server->run(error)) {
                {
                    std::scoped_lock lock(error_mutex);
                    service_error = error;
                    service_ok = false;
                }
                interrupted = true;
                lora_server->stop();
            }
        });
    }

    std::thread signal_watcher([&] {
        while (!interrupted) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (http_server) http_server->stop();
        if (lora_server) lora_server->stop();
    });

    std::string foreground_error;
    bool foreground_ok = true;
    if (lora_server) {
        foreground_ok = lora_server->run(foreground_error);
    } else {
        foreground_ok = http_server->run(foreground_error);
    }
    interrupted = true;
    signal_watcher.join();
    if (http_thread.joinable()) http_thread.join();
    tracker.stop();
    capture.stop();
    if (!foreground_ok || !service_ok) {
        std::scoped_lock lock(error_mutex);
        std::cerr << (!foreground_error.empty() ? foreground_error : service_error) << '\n';
        return 1;
    }
    return 0;
}
