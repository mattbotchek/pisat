#include "pisat/pisat.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <regex>
#include <sstream>
#include <stdexcept>

#ifndef _WIN32
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#if defined(__linux__)
#include <pigpio.h>
#endif
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include "sx126x.h"
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>

namespace fs = std::filesystem;

namespace pisat {
namespace {

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::vector<std::string> split_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::string field;
    bool quoted = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '"') {
            if (quoted && i + 1 < line.size() && line[i + 1] == '"') {
                field.push_back('"');
                ++i;
            } else {
                quoted = !quoted;
            }
        } else if (c == ',' && !quoted) {
            fields.push_back(trim(field));
            field.clear();
        } else {
            field.push_back(c);
        }
    }
    fields.push_back(trim(field));
    return fields;
}

std::string read_file(const std::string& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return {};
    }
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

[[maybe_unused]] std::string status_text(int status) {
    switch (status) {
    case 200: return "OK";
    case 202: return "Accepted";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 404: return "Not Found";
    case 409: return "Conflict";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    default: return "Error";
    }
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool parse_config_bool(const std::string& value) {
    const auto normalized = lower(value);
    if (normalized == "true" || normalized == "yes" || normalized == "1") return true;
    if (normalized == "false" || normalized == "no" || normalized == "0") return false;
    throw std::runtime_error("invalid boolean value: " + value);
}

std::vector<std::string> split(const std::string& value, char separator) {
    std::vector<std::string> result;
    std::size_t start = 0;
    while (true) {
        const auto end = value.find(separator, start);
        result.push_back(value.substr(start, end == std::string::npos ? end : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result;
}

std::string lora_escape(const std::string& value) {
    std::ostringstream out;
    out << std::uppercase << std::hex;
    for (const unsigned char c : value) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == ':') {
            out << static_cast<char>(c);
        } else {
            out << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
    }
    return out.str();
}

class Sha256 {
public:
    void update(const unsigned char* data, std::size_t length) {
        for (std::size_t i = 0; i < length; ++i) {
            buffer_[buffer_length_++] = data[i];
            if (buffer_length_ == 64) {
                transform(buffer_.data());
                bit_length_ += 512;
                buffer_length_ = 0;
            }
        }
    }

    std::array<unsigned char, 32> finish() {
        const auto original_length = buffer_length_;
        buffer_[buffer_length_++] = 0x80;
        if (buffer_length_ > 56) {
            while (buffer_length_ < 64) buffer_[buffer_length_++] = 0;
            transform(buffer_.data());
            buffer_length_ = 0;
        }
        while (buffer_length_ < 56) buffer_[buffer_length_++] = 0;
        bit_length_ += original_length * 8;
        for (int i = 7; i >= 0; --i)
            buffer_[buffer_length_++] = static_cast<unsigned char>(bit_length_ >> (i * 8));
        transform(buffer_.data());

        std::array<unsigned char, 32> digest{};
        for (std::size_t i = 0; i < state_.size(); ++i) {
            digest[i * 4] = static_cast<unsigned char>(state_[i] >> 24);
            digest[i * 4 + 1] = static_cast<unsigned char>(state_[i] >> 16);
            digest[i * 4 + 2] = static_cast<unsigned char>(state_[i] >> 8);
            digest[i * 4 + 3] = static_cast<unsigned char>(state_[i]);
        }
        return digest;
    }

private:
    static std::uint32_t rotate_right(std::uint32_t value, int bits) {
        return (value >> bits) | (value << (32 - bits));
    }

    void transform(const unsigned char* block) {
        static constexpr std::array<std::uint32_t, 64> constants = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };
        std::array<std::uint32_t, 64> words{};
        for (std::size_t i = 0; i < 16; ++i) {
            words[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
                       (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                       (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                       static_cast<std::uint32_t>(block[i * 4 + 3]);
        }
        for (std::size_t i = 16; i < 64; ++i) {
            const auto s0 = rotate_right(words[i - 15], 7) ^
                            rotate_right(words[i - 15], 18) ^ (words[i - 15] >> 3);
            const auto s1 = rotate_right(words[i - 2], 17) ^
                            rotate_right(words[i - 2], 19) ^ (words[i - 2] >> 10);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }
        auto a = state_[0]; auto b = state_[1]; auto c = state_[2]; auto d = state_[3];
        auto e = state_[4]; auto f = state_[5]; auto g = state_[6]; auto h = state_[7];
        for (std::size_t i = 0; i < 64; ++i) {
            const auto s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            const auto choice = (e & f) ^ (~e & g);
            const auto temp1 = h + s1 + choice + constants[i] + words[i];
            const auto s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            const auto majority = (a & b) ^ (a & c) ^ (b & c);
            const auto temp2 = s0 + majority;
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }

    std::array<std::uint32_t, 8> state_ = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    std::array<unsigned char, 64> buffer_{};
    std::size_t buffer_length_ = 0;
    std::uint64_t bit_length_ = 0;
};

std::array<unsigned char, 32> sha256(const std::string& value) {
    Sha256 hash;
    hash.update(reinterpret_cast<const unsigned char*>(value.data()), value.size());
    return hash.finish();
}

bool valid_frame_identifier(const std::string& value) {
    static const std::regex pattern(R"(^[A-Za-z0-9_.:-]{1,32}$)");
    return std::regex_match(value, pattern);
}

std::string base64_encode(const unsigned char* data, std::size_t size) {
    if (size == 0) return {};
    std::string encoded(4 * ((size + 2) / 3), '\0');
    const auto count = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(encoded.data()), data, static_cast<int>(size));
    if (count < 0) return {};
    encoded.resize(static_cast<std::size_t>(count));
    return encoded;
}

std::optional<std::vector<unsigned char>> base64_decode(const std::string& value) {
    if (value.empty()) return std::vector<unsigned char>{};
    if (value.size() % 4 != 0) return std::nullopt;
    std::vector<unsigned char> decoded((value.size() / 4) * 3);
    const auto count = EVP_DecodeBlock(
        decoded.data(), reinterpret_cast<const unsigned char*>(value.data()),
        static_cast<int>(value.size()));
    if (count < 0) return std::nullopt;
    std::size_t actual = static_cast<std::size_t>(count);
    if (!value.empty() && value.back() == '=') --actual;
    if (value.size() > 1 && value[value.size() - 2] == '=') --actual;
    decoded.resize(actual);
    return decoded;
}

std::array<unsigned char, 12> secure_iv(const std::string& source, std::uint64_t nonce) {
    const auto source_hash = sha256(source);
    std::array<unsigned char, 12> iv{};
    std::copy_n(source_hash.begin(), 4, iv.begin());
    for (int i = 0; i < 8; ++i)
        iv[4 + i] = static_cast<unsigned char>(nonce >> ((7 - i) * 8));
    return iv;
}

bool aes_gcm_encrypt(const std::string& plaintext, const std::string& aad,
                     const std::array<unsigned char, 32>& key,
                     const std::array<unsigned char, 12>& iv,
                     std::vector<unsigned char>& ciphertext,
                     std::array<unsigned char, 16>& tag) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) return false;
    if (EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) != 1)
        return false;
    int length = 0;
    if (EVP_EncryptUpdate(context.get(), nullptr, &length,
                          reinterpret_cast<const unsigned char*>(aad.data()),
                          static_cast<int>(aad.size())) != 1)
        return false;
    ciphertext.resize(plaintext.size() + 16);
    int total = 0;
    if (EVP_EncryptUpdate(context.get(), ciphertext.data(), &length,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1)
        return false;
    total += length;
    if (EVP_EncryptFinal_ex(context.get(), ciphertext.data() + total, &length) != 1)
        return false;
    total += length;
    ciphertext.resize(static_cast<std::size_t>(total));
    return EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG,
                               static_cast<int>(tag.size()), tag.data()) == 1;
}

bool aes_gcm_decrypt(const std::vector<unsigned char>& ciphertext, const std::string& aad,
                     const std::array<unsigned char, 32>& key,
                     const std::array<unsigned char, 12>& iv,
                     const std::array<unsigned char, 16>& tag,
                     std::string& plaintext) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) return false;
    if (EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) != 1)
        return false;
    int length = 0;
    if (EVP_DecryptUpdate(context.get(), nullptr, &length,
                          reinterpret_cast<const unsigned char*>(aad.data()),
                          static_cast<int>(aad.size())) != 1)
        return false;
    std::vector<unsigned char> output(ciphertext.size() + 16);
    int total = 0;
    if (EVP_DecryptUpdate(context.get(), output.data(), &length, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1)
        return false;
    total += length;
    auto mutable_tag = tag;
    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(mutable_tag.size()), mutable_tag.data()) != 1 ||
        EVP_DecryptFinal_ex(context.get(), output.data() + total, &length) != 1)
        return false;
    total += length;
    plaintext.assign(reinterpret_cast<const char*>(output.data()),
                     static_cast<std::size_t>(total));
    return true;
}

#ifndef _WIN32
speed_t serial_speed(int baud) {
    switch (baud) {
    case 1200: return B1200;
    case 2400: return B2400;
    case 4800: return B4800;
    case 9600: return B9600;
    case 19200: return B19200;
    case 38400: return B38400;
    case 57600: return B57600;
    case 115200: return B115200;
    default: return 0;
    }
}
#endif

} // namespace

Config Config::load(const std::string& path) {
    Config config;
    std::ifstream stream(path);
    if (!stream) {
        throw std::runtime_error("cannot open configuration: " + path);
    }
    std::string line;
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line.front() == '#') {
            continue;
        }
        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            throw std::runtime_error("invalid configuration line: " + line);
        }
        const auto key = trim(line.substr(0, separator));
        const auto value = trim(line.substr(separator + 1));
        if (key == "interface") config.interface = value;
        else if (key == "bind_address") config.bind_address = value;
        else if (key == "http_enabled") config.http_enabled = parse_config_bool(value);
        else if (key == "port") {
            const int port = std::stoi(value);
            if (port < 1 || port > 65535) throw std::runtime_error("port must be between 1 and 65535");
            config.port = static_cast<std::uint16_t>(port);
        }
        else if (key == "api_token") config.api_token = value;
        else if (key == "lora_enabled") config.lora_enabled = parse_config_bool(value);
        else if (key == "lora_device") config.lora_device = value;
        else if (key == "lora_baud") config.lora_baud = std::stoi(value);
        else if (key == "lora_node_id") config.lora_node_id = value;
        else if (key == "lora_key") config.lora_key = value;
        else if (key == "lora_allowed_controllers") {
            config.lora_allowed_controllers.clear();
            for (auto controller : split(value, ',')) {
                controller = trim(controller);
                if (!controller.empty()) config.lora_allowed_controllers.push_back(controller);
            }
        }
        else if (key == "lora_m0_gpio") config.lora_m0_gpio = std::stoi(value);
        else if (key == "lora_m1_gpio") config.lora_m1_gpio = std::stoi(value);
        else if (key == "lora_aux_gpio") config.lora_aux_gpio = std::stoi(value);
        else if (key == "lora_aux_active_high")
            config.lora_aux_active_high = parse_config_bool(value);
        else if (key == "lora_aux_timeout_ms") config.lora_aux_timeout_ms = std::stoi(value);
        else if (key == "lora_publish_interval_seconds")
            config.lora_publish_interval_seconds = std::stoi(value);
        else if (key == "lora_max_frame_bytes") config.lora_max_frame_bytes = std::stoi(value);
        else if (key == "data_directory") config.data_directory = value;
        else if (key == "default_engine") config.default_engine = value;
        else if (key == "default_channel") config.default_channel = std::stoi(value);
        else if (key == "device_ttl_seconds") config.device_ttl_seconds = std::stoi(value);
        else throw std::runtime_error("unknown configuration key: " + key);
    }
    if (!valid_interface_name(config.interface)) {
        throw std::runtime_error("invalid interface name");
    }
    if (config.port == 0) {
        throw std::runtime_error("port must be between 1 and 65535");
    }
    if (config.default_channel < 0 || config.default_channel > 196) {
        throw std::runtime_error("default_channel must be between 0 and 196");
    }
    if (config.device_ttl_seconds < 0) {
        throw std::runtime_error("device_ttl_seconds cannot be negative");
    }
    if (!config.http_enabled && !config.lora_enabled) {
        throw std::runtime_error("at least one service transport must be enabled");
    }
    if (config.lora_enabled) {
        if (config.lora_key.size() < 16)
            throw std::runtime_error("lora_key must contain at least 16 characters");
        if (config.lora_key == "replace-with-a-random-32-byte-key")
            throw std::runtime_error("replace the default lora_key before starting PiSAT");
        static const std::regex node_pattern(R"(^[A-Za-z0-9_.:-]{1,32}$)");
        if (!std::regex_match(config.lora_node_id, node_pattern))
            throw std::runtime_error("lora_node_id is invalid");
        if (config.lora_node_id == "replace-with-unique-node-id" ||
            config.lora_node_id == "pisat")
            throw std::runtime_error(
                "set lora_node_id to a globally unique ID before starting PiSAT");
        if (config.lora_allowed_controllers.empty())
            throw std::runtime_error("lora_allowed_controllers cannot be empty");
        for (const auto& controller : config.lora_allowed_controllers) {
            if (!std::regex_match(controller, node_pattern) ||
                controller == "replace-with-authorized-pitak-id" ||
                controller == config.lora_node_id)
                throw std::runtime_error("lora_allowed_controllers contains an invalid ID");
        }
        if (config.lora_device.empty())
            throw std::runtime_error("lora_device cannot be empty");
        const auto valid_gpio = [](int pin) { return pin >= 0 && pin <= 53; };
        if (!valid_gpio(config.lora_m0_gpio) || !valid_gpio(config.lora_m1_gpio) ||
            !valid_gpio(config.lora_aux_gpio))
            throw std::runtime_error("LoRa GPIO pins must be between 0 and 53");
        if (config.lora_m0_gpio == config.lora_m1_gpio ||
            config.lora_m0_gpio == config.lora_aux_gpio ||
            config.lora_m1_gpio == config.lora_aux_gpio)
            throw std::runtime_error("LoRa GPIO pins must be unique");
        if (config.lora_aux_timeout_ms < 100 || config.lora_aux_timeout_ms > 30000)
            throw std::runtime_error("lora_aux_timeout_ms must be between 100 and 30000");
        if (config.lora_max_frame_bytes < 96 || config.lora_max_frame_bytes > 255)
            throw std::runtime_error("lora_max_frame_bytes must be between 96 and 255");
        if (config.lora_publish_interval_seconds < 0)
            throw std::runtime_error("lora_publish_interval_seconds cannot be negative");
    }
    return config;
}

Process::Process(Process&& other) noexcept : pid_(other.pid_) {
    other.pid_ = -1;
}

Process& Process::operator=(Process&& other) noexcept {
    if (this != &other) {
        stop();
        pid_ = other.pid_;
        other.pid_ = -1;
    }
    return *this;
}

Process::~Process() {
    stop();
}

bool Process::start(const std::vector<std::string>& args,
                    const std::optional<std::string>& output_file) {
    if (args.empty() || running()) {
        return false;
    }
#ifdef _WIN32
    (void)output_file;
    return false;
#else
    const pid_t child = fork();
    if (child < 0) {
        return false;
    }
    if (child == 0) {
        if (output_file) {
            const int fd = open(output_file->c_str(), O_WRONLY | O_CREAT | O_APPEND, 0640);
            if (fd < 0) _exit(126);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);
        execvp(argv.front(), argv.data());
        _exit(127);
    }
    pid_ = child;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    int status = 0;
    if (waitpid(child, &status, WNOHANG) == child) {
        pid_ = -1;
        return false;
    }
    return true;
#endif
}

void Process::stop(std::chrono::milliseconds grace) {
#ifdef _WIN32
    (void)grace;
#else
    if (pid_ <= 0) return;
    kill(static_cast<pid_t>(pid_), SIGTERM);
    const auto deadline = std::chrono::steady_clock::now() + grace;
    int status = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        if (waitpid(static_cast<pid_t>(pid_), &status, WNOHANG) == pid_) {
            pid_ = -1;
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    kill(static_cast<pid_t>(pid_), SIGKILL);
    waitpid(static_cast<pid_t>(pid_), &status, 0);
#endif
    pid_ = -1;
}

bool Process::running() const {
#ifdef _WIN32
    return false;
#else
    if (pid_ <= 0) return false;
    int status = 0;
    if (waitpid(static_cast<pid_t>(pid_), &status, WNOHANG) == pid_) {
        pid_ = -1;
        return false;
    }
    return kill(static_cast<pid_t>(pid_), 0) == 0 || errno == EPERM;
#endif
}

long Process::id() const {
    return pid_;
}

CommandResult run_command(const std::vector<std::string>& args) {
    CommandResult result;
    if (args.empty()) return result;
#ifdef _WIN32
    result.output = "command execution is supported on Linux only";
    return result;
#else
    int pipe_fd[2];
    if (pipe(pipe_fd) != 0) {
        result.output = std::strerror(errno);
        return result;
    }
    const pid_t child = fork();
    if (child < 0) {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        result.output = std::strerror(errno);
        return result;
    }
    if (child == 0) {
        close(pipe_fd[0]);
        dup2(pipe_fd[1], STDOUT_FILENO);
        dup2(pipe_fd[1], STDERR_FILENO);
        close(pipe_fd[1]);
        std::vector<char*> argv;
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr);
        execvp(argv.front(), argv.data());
        _exit(127);
    }
    close(pipe_fd[1]);
    std::array<char, 4096> buffer{};
    ssize_t count = 0;
    while ((count = read(pipe_fd[0], buffer.data(), buffer.size())) > 0) {
        result.output.append(buffer.data(), static_cast<std::size_t>(count));
    }
    close(pipe_fd[0]);
    int status = 0;
    waitpid(child, &status, 0);
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    return result;
#endif
}

bool valid_interface_name(const std::string& value) {
    static const std::regex pattern(R"(^[A-Za-z0-9_.:-]{1,15}$)");
    return std::regex_match(value, pattern);
}

MonitorController::MonitorController(std::string interface)
    : interface_(std::move(interface)) {}

CommandResult MonitorController::set_enabled(bool enabled, int channel) const {
    if (!valid_interface_name(interface_)) return {-1, "invalid interface name"};
    if (channel < 0 || channel > 196) return {-1, "channel must be between 1 and 196"};

    auto result = run_command({"ip", "link", "set", "dev", interface_, "down"});
    if (result.exit_code != 0) return result;
    result = run_command({"iw", "dev", interface_, "set", "type", enabled ? "monitor" : "managed"});
    if (result.exit_code != 0) {
        run_command({"ip", "link", "set", "dev", interface_, "up"});
        return result;
    }
    result = run_command({"ip", "link", "set", "dev", interface_, "up"});
    if (result.exit_code != 0) return result;
    if (enabled && channel > 0) {
        result = run_command({"iw", "dev", interface_, "set", "channel", std::to_string(channel)});
    }
    return result;
}

bool MonitorController::is_monitor_mode() const {
    const auto result = run_command({"iw", "dev", interface_, "info"});
    return result.exit_code == 0 &&
           (result.output.find("type monitor") != std::string::npos ||
            result.output.find("type\tmonitor") != std::string::npos);
}

std::optional<CaptureEngine> parse_capture_engine(const std::string& value) {
    const auto normalized = lower(value);
    if (normalized == "tcpdump") return CaptureEngine::tcpdump;
    if (normalized == "airodump" || normalized == "airodump-ng") return CaptureEngine::airodump;
    if (normalized == "wireshark" || normalized == "dumpcap") return CaptureEngine::wireshark;
    return std::nullopt;
}

std::string capture_engine_name(CaptureEngine engine) {
    switch (engine) {
    case CaptureEngine::tcpdump: return "tcpdump";
    case CaptureEngine::airodump: return "airodump-ng";
    case CaptureEngine::wireshark: return "dumpcap";
    }
    return "unknown";
}

CaptureManager::CaptureManager(std::string interface) : interface_(std::move(interface)) {}
CaptureManager::~CaptureManager() { stop(); }

bool CaptureManager::start(CaptureEngine engine, const std::string& output, std::string& error) {
    std::scoped_lock lock(mutex_);
    if (process_.running()) {
        error = "a capture is already active";
        return false;
    }
    if (output.empty()) {
        error = "output path is required";
        return false;
    }
    std::error_code ec;
    const fs::path output_path(output);
    if (output_path.has_parent_path()) fs::create_directories(output_path.parent_path(), ec);
    if (ec) {
        error = "cannot create output directory: " + ec.message();
        return false;
    }

    std::vector<std::string> args;
    switch (engine) {
    case CaptureEngine::tcpdump:
        args = {"tcpdump", "-i", interface_, "-U", "-s", "0", "-w", output};
        break;
    case CaptureEngine::airodump:
        args = {"airodump-ng", "--write", output, "--output-format", "pcap,csv",
                "--write-interval", "1", interface_};
        break;
    case CaptureEngine::wireshark:
        args = {"dumpcap", "-i", interface_, "-q", "-w", output};
        break;
    }
    if (!process_.start(args)) {
        error = "failed to start " + capture_engine_name(engine) +
                "; verify it is installed and the service has capture privileges";
        status_ = {};
        status_.error = error;
        return false;
    }
    const auto reported_output =
        engine == CaptureEngine::airodump ? output + "-01.cap" : output;
    status_ = {true, capture_engine_name(engine), reported_output, process_.id(), {}};
    return true;
}

void CaptureManager::stop() {
    std::scoped_lock lock(mutex_);
    process_.stop();
    status_.active = false;
    status_.pid = -1;
}

CaptureStatus CaptureManager::status() const {
    std::scoped_lock lock(mutex_);
    auto copy = status_;
    copy.active = process_.running();
    if (!copy.active) copy.pid = -1;
    return copy;
}

std::vector<WirelessDevice> parse_airodump_csv(const std::string& text) {
    std::vector<WirelessDevice> devices;
    std::istringstream stream(text);
    std::string line;
    bool clients = false;
    while (std::getline(stream, line)) {
        if (line.find("Station MAC") != std::string::npos) {
            clients = true;
            continue;
        }
        if (line.find("BSSID") == 0) {
            clients = false;
            continue;
        }
        const auto fields = split_csv_line(line);
        if (fields.empty() || fields[0].empty()) continue;
        static const std::regex mac_pattern(R"(^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$)");
        if (!std::regex_match(fields[0], mac_pattern)) continue;

        WirelessDevice device;
        device.mac = fields[0];
        device.kind = clients ? "station" : "access_point";
        if (!clients && fields.size() >= 14) {
            device.first_seen = fields[1];
            device.last_seen = fields[2];
            device.channel = fields[3];
            device.signal_dbm = fields[8];
            device.packets = fields[10];
            device.essid = fields[13];
        } else if (clients && fields.size() >= 7) {
            device.first_seen = fields[1];
            device.last_seen = fields[2];
            device.signal_dbm = fields[3];
            device.packets = fields[4];
            device.bssid = fields[5] == "(not associated)" ? "" : fields[5];
            device.essid = fields[6];
        }
        devices.push_back(std::move(device));
    }
    return devices;
}

std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (const unsigned char c : value) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) {
                out << "\\u00";
                constexpr char hex[] = "0123456789abcdef";
                out << hex[c >> 4] << hex[c & 0x0f];
            } else {
                out << static_cast<char>(c);
            }
        }
    }
    return out.str();
}

std::string devices_to_json(const std::vector<WirelessDevice>& devices) {
    std::ostringstream out;
    out << "{\"count\":" << devices.size() << ",\"devices\":[";
    for (std::size_t i = 0; i < devices.size(); ++i) {
        if (i) out << ',';
        const auto& d = devices[i];
        out << "{\"mac\":\"" << json_escape(d.mac)
            << "\",\"kind\":\"" << json_escape(d.kind)
            << "\",\"first_seen\":\"" << json_escape(d.first_seen)
            << "\",\"last_seen\":\"" << json_escape(d.last_seen)
            << "\",\"channel\":\"" << json_escape(d.channel)
            << "\",\"signal_dbm\":\"" << json_escape(d.signal_dbm)
            << "\",\"packets\":\"" << json_escape(d.packets)
            << "\",\"bssid\":\"" << json_escape(d.bssid)
            << "\",\"essid\":\"" << json_escape(d.essid)
            << "\"}";
    }
    out << "]}";
    return out.str();
}

std::string devices_to_lora_page(const std::vector<WirelessDevice>& devices,
                                 std::size_t offset, std::size_t limit) {
    offset = std::min(offset, devices.size());
    limit = std::min<std::size_t>(limit, 1);
    const auto end = std::min(devices.size(), offset + limit);
    std::ostringstream out;
    out << offset << ',' << devices.size();
    for (std::size_t i = offset; i < end; ++i) {
        const auto& device = devices[i];
        auto essid = lora_escape(device.essid);
        if (essid.size() > 24) essid.resize(24);
        out << ';' << (device.kind == "access_point" ? "A" : "S")
            << ',' << device.mac
            << ',' << lora_escape(device.signal_dbm)
            << ',' << lora_escape(device.channel)
            << ',' << essid;
    }
    return out.str();
}

DeviceTracker::DeviceTracker(std::string interface, std::string data_directory, int ttl_seconds)
    : interface_(std::move(interface)),
      data_directory_(std::move(data_directory)),
      prefix_((fs::path(data_directory_) / "survey").string()),
      ttl_seconds_(ttl_seconds) {}

DeviceTracker::~DeviceTracker() { stop(); }

bool DeviceTracker::start(std::string& error) {
    if (survey_.running()) return true;
    std::error_code ec;
    fs::create_directories(data_directory_, ec);
    if (ec) {
        error = "cannot create data directory: " + ec.message();
        return false;
    }
    for (const auto& entry : fs::directory_iterator(data_directory_, ec)) {
        if (entry.path().filename().string().starts_with("survey-")) fs::remove(entry.path(), ec);
    }
    if (!survey_.start({"airodump-ng", "--write", prefix_, "--output-format", "csv",
                        "--write-interval", "1", interface_},
                       (fs::path(data_directory_) / "survey.log").string())) {
        error = "failed to start airodump-ng survey";
        return false;
    }
    stop_requested_ = false;
    refresh_thread_ = std::thread(&DeviceTracker::refresh_loop, this);
    return true;
}

void DeviceTracker::stop() {
    stop_requested_ = true;
    if (refresh_thread_.joinable()) refresh_thread_.join();
    survey_.stop();
}

std::vector<WirelessDevice> DeviceTracker::snapshot() const {
    std::scoped_lock lock(mutex_);
    std::vector<WirelessDevice> result;
    result.reserve(devices_.size());
    for (const auto& [_, device] : devices_) result.push_back(device);
    return result;
}

std::string DeviceTracker::csv_path() const {
    return prefix_ + "-01.csv";
}

void DeviceTracker::refresh_loop() {
    while (!stop_requested_) {
        const auto parsed = parse_airodump_csv(read_file(csv_path()));
        const auto now = std::chrono::steady_clock::now();
        {
            std::scoped_lock lock(mutex_);
            for (const auto& device : parsed) {
                const auto key = device.kind + ":" + device.mac;
                devices_[key] = device;
                last_observed_[key] = now;
            }
            if (ttl_seconds_ > 0) {
                for (auto it = last_observed_.begin(); it != last_observed_.end();) {
                    if (now - it->second > std::chrono::seconds(ttl_seconds_)) {
                        devices_.erase(it->first);
                        it = last_observed_.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

std::optional<bool> json_boolean(const std::string& body, const std::string& key) {
    const std::regex pattern("\"" + key + R"("\s*:\s*(true|false))");
    std::smatch match;
    if (!std::regex_search(body, match, pattern)) return std::nullopt;
    return match[1] == "true";
}

std::optional<int> json_integer(const std::string& body, const std::string& key) {
    const std::regex pattern("\"" + key + R"("\s*:\s*(-?[0-9]+))");
    std::smatch match;
    if (!std::regex_search(body, match, pattern)) return std::nullopt;
    const auto value = match[1].str();
    int parsed = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size()) return std::nullopt;
    return parsed;
}

std::optional<std::string> json_string(const std::string& body, const std::string& key) {
    const std::regex pattern("\"" + key + R"json("\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)")json");
    std::smatch match;
    if (!std::regex_search(body, match, pattern)) return std::nullopt;
    return match[1];
}

std::string make_secure_lora_frame(const std::string& source, const std::string& target,
                                   std::uint64_t nonce, const std::string& type,
                                   const std::string& payload, const std::string& key) {
    if (nonce == 0 || !valid_frame_identifier(source) ||
        !(target == "*" || valid_frame_identifier(target)) ||
        !valid_frame_identifier(type) || key.empty())
        return {};
    const std::string aad = "P2|" + source + "|" + target + "|" +
                            std::to_string(nonce) + "|" + type;
    const auto encryption_key = sha256(key);
    const auto iv = secure_iv(source, nonce);
    std::vector<unsigned char> ciphertext;
    std::array<unsigned char, 16> tag{};
    if (!aes_gcm_encrypt(payload, aad, encryption_key, iv, ciphertext, tag)) return {};
    return aad + "|" + base64_encode(ciphertext.data(), ciphertext.size()) +
           "|" + base64_encode(tag.data(), tag.size());
}

std::optional<LoRaRequest> parse_secure_lora_frame(
    const std::string& frame, const std::string& node_id, const std::string& key,
    std::map<std::string, std::uint64_t>& last_nonces, std::string& error) {
    const auto normalized = trim(frame);
    const auto fields = split(normalized, '|');
    if (fields.size() != 7 || fields[0] != "P2") {
        error = "FORMAT";
        return std::nullopt;
    }
    if (!valid_frame_identifier(fields[1]) ||
        !(fields[2] == "*" || valid_frame_identifier(fields[2])) ||
        !valid_frame_identifier(fields[4]) ||
        (fields[2] != node_id && fields[2] != "*")) {
        error = "ROUTE";
        return std::nullopt;
    }
    std::uint64_t nonce = 0;
    const auto [end, parse_error] =
        std::from_chars(fields[3].data(), fields[3].data() + fields[3].size(), nonce);
    const auto previous = last_nonces.find(fields[1]);
    const auto previous_nonce = previous == last_nonces.end() ? 0 : previous->second;
    if (parse_error != std::errc{} || end != fields[3].data() + fields[3].size() ||
        nonce == 0 || nonce <= previous_nonce) {
        error = "REPLAY";
        return std::nullopt;
    }
    const auto ciphertext = base64_decode(fields[5]);
    const auto decoded_tag = base64_decode(fields[6]);
    if (!ciphertext || !decoded_tag || decoded_tag->size() != 16) {
        error = "FORMAT";
        return std::nullopt;
    }
    std::array<unsigned char, 16> tag{};
    std::copy(decoded_tag->begin(), decoded_tag->end(), tag.begin());
    const std::string aad = "P2|" + fields[1] + "|" + fields[2] + "|" +
                            fields[3] + "|" + fields[4];
    std::string plaintext;
    if (!aes_gcm_decrypt(*ciphertext, aad, sha256(key), secure_iv(fields[1], nonce),
                         tag, plaintext)) {
        error = "AUTH";
        return std::nullopt;
    }
    last_nonces[fields[1]] = nonce;
    return LoRaRequest{nonce, fields[1], fields[2], fields[4], plaintext};
}

std::pair<int, int> sx126x_mode_levels(const std::string& mode) {
    const auto normalized = lower(mode);
    if (normalized == "normal") return {0, 0};
    if (normalized == "configuration" || normalized == "config") return {1, 1};
    return {-1, -1};
}

HttpServer::HttpServer(std::string address, std::uint16_t port, Handler handler)
    : address_(std::move(address)), port_(port), handler_(std::move(handler)) {}

HttpServer::~HttpServer() { stop(); }

bool HttpServer::run(std::string& error) {
#ifdef _WIN32
    error = "HTTP server is supported on Linux only";
    return false;
#else
    socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_ < 0) {
        error = std::strerror(errno);
        return false;
    }
    int reuse = 1;
    setsockopt(static_cast<int>(socket_), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port_);
    if (inet_pton(AF_INET, address_.c_str(), &address.sin_addr) != 1) {
        error = "bind_address must be an IPv4 address";
        stop();
        return false;
    }
    if (bind(static_cast<int>(socket_), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        listen(static_cast<int>(socket_), 16) != 0) {
        error = std::strerror(errno);
        stop();
        return false;
    }

    while (!stop_requested_) {
        const int client = accept(static_cast<int>(socket_), nullptr, nullptr);
        if (client < 0) {
            if (stop_requested_) break;
            continue;
        }
#ifndef _WIN32
        timeval timeout{};
        timeout.tv_sec = 5;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif
        std::string raw;
        std::array<char, 8192> buffer{};
        std::size_t expected = std::string::npos;
        bool valid_wire = true;
        while (raw.size() < 1024 * 1024) {
            const auto count = recv(client, buffer.data(), buffer.size(), 0);
            if (count <= 0) break;
            raw.append(buffer.data(), static_cast<std::size_t>(count));
            const auto header_end = raw.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                if (expected == std::string::npos) {
                    expected = header_end + 4;
                    const std::regex content_length(R"(Content-Length:\s*([0-9]+))",
                                                    std::regex::icase);
                    std::smatch match;
                    if (std::regex_search(raw, match, content_length)) {
                        const auto value = match[1].str();
                        std::size_t length = 0;
                        const auto [end, parse_error] =
                            std::from_chars(value.data(), value.data() + value.size(), length);
                        if (parse_error != std::errc{} ||
                            end != value.data() + value.size() ||
                            length > 1024 * 1024 - expected) {
                            valid_wire = false;
                            break;
                        }
                        expected += length;
                    }
                }
                if (raw.size() >= expected) break;
            }
        }

        HttpResponse response{400, "application/json", "{\"error\":\"invalid request\"}"};
        const auto header_end = raw.find("\r\n\r\n");
        if (valid_wire && header_end != std::string::npos &&
            expected != std::string::npos && raw.size() >= expected) {
            HttpRequest request;
            std::istringstream headers(raw.substr(0, header_end));
            std::string line;
            if (std::getline(headers, line)) {
                std::istringstream first(trim(line));
                first >> request.method >> request.path;
            }
            while (std::getline(headers, line)) {
                const auto separator = line.find(':');
                if (separator != std::string::npos)
                    request.headers[lower(trim(line.substr(0, separator)))] =
                        trim(line.substr(separator + 1));
            }
            request.body = raw.substr(header_end + 4);
            try {
                response = handler_(request);
            } catch (const std::exception&) {
                response = {500, "application/json", "{\"error\":\"request processing failed\"}"};
            }
        }
        const std::string wire = "HTTP/1.1 " + std::to_string(response.status) + " " +
            status_text(response.status) + "\r\nContent-Type: " + response.content_type +
            "\r\nContent-Length: " + std::to_string(response.body.size()) +
            "\r\nConnection: close\r\n\r\n" + response.body;
        send(client, wire.data(), wire.size(), 0);
        close(client);
    }
    stop();
    return true;
#endif
}

void HttpServer::stop() {
    stop_requested_ = true;
#ifndef _WIN32
    if (socket_ >= 0) {
        shutdown(static_cast<int>(socket_), SHUT_RDWR);
        close(static_cast<int>(socket_));
    }
#endif
    socket_ = -1;
}

LoRaServer::LoRaServer(std::string device, int baud, std::string node_id, std::string key,
                       std::string nonce_file,
                       int m0_gpio, int m1_gpio, int aux_gpio, bool aux_active_high,
                       int aux_timeout_ms,
                       int max_frame_bytes, int publish_interval_seconds,
                       Handler handler, Publisher publisher)
    : device_(std::move(device)),
      baud_(baud),
      node_id_(std::move(node_id)),
      key_(std::move(key)),
      nonce_file_(std::move(nonce_file)),
      m0_gpio_(m0_gpio),
      m1_gpio_(m1_gpio),
      aux_gpio_(aux_gpio),
      aux_active_high_(aux_active_high),
      aux_timeout_ms_(aux_timeout_ms),
      max_frame_bytes_(max_frame_bytes),
      publish_interval_seconds_(publish_interval_seconds),
      handler_(std::move(handler)),
      publisher_(std::move(publisher)) {}

LoRaServer::~LoRaServer() {
    stop();
    shutdown_hat();
}

bool LoRaServer::write_frame(const std::string& frame) {
#ifdef _WIN32
    (void)frame;
    return false;
#else
    if (!sx126x_ || !sx126x_->isReady() || frame.size() + 1 > static_cast<std::size_t>(max_frame_bytes_))
        return false;
    return sx126x_->send(frame + "\n");
#endif
}

bool LoRaServer::initialize_hat(std::string& error) {
#ifdef _WIN32
    error = "pigpio HAT control is supported on Linux only";
    return false;
#else
    sx126x_ = std::make_unique<SX126X>(device_, baud_, m0_gpio_, m1_gpio_, aux_gpio_, aux_active_high_);
    if (!sx126x_ || !sx126x_->isReady()) {
        error = "failed to initialize SX126x HAT";
        sx126x_.reset();
        return false;
    }
    return true;
#endif
}

bool LoRaServer::wait_hat_ready(std::string& error) const {
#ifdef _WIN32
    error = "pigpio HAT control is supported on Linux only";
    return false;
#else
    if (!sx126x_ || !sx126x_->isReady()) {
        error = "SX126x is not initialized";
        return false;
    }
    return true;
#endif
}

void LoRaServer::shutdown_hat() {
#ifndef _WIN32
    sx126x_.reset();
#endif
}

std::uint64_t LoRaServer::next_outbound_nonce() {
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const auto timestamp = now > 0 ? static_cast<std::uint64_t>(now) : 1;
    outbound_nonce_ = std::max(outbound_nonce_ + 1, timestamp);
    const auto path = nonce_file_ + ".outbound";
    const auto temporary = path + ".tmp";
    std::ofstream stream(temporary, std::ios::trunc);
    stream << outbound_nonce_ << '\n';
    stream.close();
    std::error_code rename_error;
    fs::rename(temporary, path, rename_error);
    if (rename_error) {
        fs::remove(path, rename_error);
        fs::rename(temporary, path, rename_error);
    }
    if (rename_error) return 0;
    return outbound_nonce_;
}

bool LoRaServer::run(std::string& error) {
#ifdef _WIN32
    error = "LoRa serial service is supported on Linux only";
    return false;
#else
    if (!initialize_hat(error)) return false;
    {
        std::error_code state_error;
        const bool inbound_exists = fs::exists(nonce_file_, state_error);
        if (state_error) {
            error = "cannot inspect inbound nonce state: " + state_error.message();
            stop();
            shutdown_hat();
            return false;
        }
        std::ifstream nonce_stream(nonce_file_);
        if (inbound_exists && !nonce_stream) {
            error = "existing inbound nonce state is unreadable";
            stop();
            shutdown_hat();
            return false;
        }
        std::string line;
        while (std::getline(nonce_stream, line)) {
            const auto separator = line.find('=');
            if (separator == std::string::npos) continue;
            std::uint64_t nonce = 0;
            const auto value = line.substr(separator + 1);
            const auto [end, parse_error] =
                std::from_chars(value.data(), value.data() + value.size(), nonce);
            if (parse_error == std::errc{} && end == value.data() + value.size() &&
                valid_frame_identifier(line.substr(0, separator)))
                last_nonces_[line.substr(0, separator)] = nonce;
        }
        const auto outbound_path = nonce_file_ + ".outbound";
        const bool outbound_exists = fs::exists(outbound_path, state_error);
        if (state_error) {
            error = "cannot inspect outbound nonce state: " + state_error.message();
            stop();
            shutdown_hat();
            return false;
        }
        if (outbound_exists) {
            std::ifstream outbound_stream(outbound_path);
            if (!(outbound_stream >> outbound_nonce_) || outbound_nonce_ == 0) {
                error = "existing outbound nonce state is unreadable or invalid";
                stop();
                shutdown_hat();
                return false;
            }
        } else {
            std::array<unsigned char, 8> seed{};
            if (RAND_bytes(seed.data(), static_cast<int>(seed.size())) != 1) {
                error = "failed to seed outbound nonce state";
                stop();
                shutdown_hat();
                return false;
            }
            for (const auto byte : seed)
                outbound_nonce_ = (outbound_nonce_ << 8) | byte;
            outbound_nonce_ &= std::numeric_limits<std::uint64_t>::max() >> 1;
            if (outbound_nonce_ == 0) outbound_nonce_ = 1;
        }
    }

    std::string input;
    auto next_publish = std::chrono::steady_clock::now() +
                        std::chrono::seconds(publish_interval_seconds_);
    std::array<uint8_t, 256> buffer{};
    while (!stop_requested_) {
        int count = 0;
        if (sx126x_->available()) {
            count = sx126x_->receive(buffer.data(), static_cast<int>(buffer.size()));
        }
        if (count > 0) {
            input.append(reinterpret_cast<const char*>(buffer.data()),
                         static_cast<std::size_t>(count));
            if (input.size() > static_cast<std::size_t>(max_frame_bytes_) * 2) input.clear();
            std::size_t newline = 0;
            while ((newline = input.find('\n')) != std::string::npos) {
                auto frame = trim(input.substr(0, newline));
                input.erase(0, newline + 1);
                if (frame.empty() || frame.size() > static_cast<std::size_t>(max_frame_bytes_))
                    continue;
                // Many HATs/drivers may produce noise or binary preamble; extract the first occurrence
                // of the secure frame prefix "P2|" and discard anything before it.
                auto p2pos = frame.find("P2|");
                if (p2pos == std::string::npos) {
                    // not a secure frame, log a short hex preview for diagnostics and skip
                    std::ostringstream hex;
                    for (size_t i = 0; i < frame.size() && i < 32; ++i) {
                        unsigned char c = static_cast<unsigned char>(frame[i]);
                        hex << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
                    }
                    std::cerr << "Non-P2 serial data (skipping), hex=" << hex.str() << " len=" << frame.size() << "\n";
                    continue;
                }
                if (p2pos > 0) frame = frame.substr(p2pos);
                std::string parse_error;
                const auto previous_nonces = last_nonces_;
                const auto request =
                    parse_secure_lora_frame(frame, node_id_, key_, last_nonces_, parse_error);
                if (!request) {
                    std::cerr << "LoRa parse failed: " << parse_error << " frame=\"" << frame << "\"\n";
                    // log hex of the frame for debugging
                    std::ostringstream hex;
                    for (size_t i = 0; i < frame.size() && i < 128; ++i) {
                        unsigned char c = static_cast<unsigned char>(frame[i]);
                        hex << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
                    }
                    std::cerr << "frame hex=" << hex.str() << "\n";
                    continue;
                }
                bool nonce_persisted = false;
                {
                    const auto temporary = nonce_file_ + ".tmp";
                    std::ofstream nonce_stream(temporary, std::ios::trunc);
                    for (const auto& [source, nonce] : last_nonces_)
                        nonce_stream << source << '=' << nonce << '\n';
                    nonce_stream.close();
                    std::error_code rename_error;
                    fs::rename(temporary, nonce_file_, rename_error);
                    if (rename_error) {
                        fs::remove(nonce_file_, rename_error);
                        fs::rename(temporary, nonce_file_, rename_error);
                    }
                    nonce_persisted = !rename_error;
                }
                if (!nonce_persisted) {
                    last_nonces_ = previous_nonces;
                    write_frame(make_secure_lora_frame(
                        node_id_, request->source, next_outbound_nonce(),
                        "ERR", std::to_string(request->nonce) + ",NONCE_STORE", key_));
                    continue;
                }
                std::pair<std::string, std::string> response;
                try {
                    response = handler_(*request);
                } catch (const std::exception&) {
                    response = {"ERR", "INTERNAL"};
                }
                if (response.first.empty()) continue;
                auto response_frame = make_secure_lora_frame(
                    node_id_, request->source, next_outbound_nonce(), response.first,
                    std::to_string(request->nonce) + "," + response.second, key_);
                if (!write_frame(response_frame)) {
                    response_frame =
                        make_secure_lora_frame(
                            node_id_, request->source, next_outbound_nonce(), "ERR",
                            std::to_string(request->nonce) + ",TOO_LARGE", key_);
                    write_frame(response_frame);
                }
            }
        } else if (count < 0 && stop_requested_) {
            break;
        } else if (count < 0) {
            error = "LoRa serial read failed";
            stop();
            shutdown_hat();
            return false;
        }

        const auto now = std::chrono::steady_clock::now();
        if (publish_interval_seconds_ > 0 && now >= next_publish) {
            const auto payload = publisher_();
            if (!payload.empty())
                write_frame(make_secure_lora_frame(
                    node_id_, "*", next_outbound_nonce(),
                    "EVENT", payload, key_));
            next_publish = now + std::chrono::seconds(publish_interval_seconds_);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    stop();
    shutdown_hat();
    return true;
#endif
}

void LoRaServer::stop() {
    stop_requested_ = true;
}

} // namespace pisat
