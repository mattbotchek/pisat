#include <iostream>
#include <pigpio.h>
#include <cstring>
#include <chrono>

const char* UART_DEV = "/dev/ttyS0";
#define BAUD 9600

int main() {
    if (gpioInitialise() < 0) {
        std::cerr << "pigpio init failed\n";
        return 1;
    }
    int fd = serOpen((char*)UART_DEV, BAUD, 0);
    if (fd < 0) {
        std::cerr << "UART open failed\n";
        gpioTerminate();
        return 2;
    }

    std::string acc;
    auto start = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::seconds(20);
    while (std::chrono::steady_clock::now() - start < timeout) {
        if (serDataAvailable(fd) > 0) {
            char buf[256];
            int n = serRead(fd, buf, sizeof(buf)-1);
            if (n > 0) {
                buf[n] = '\0';
                acc += buf;
                if (acc.find("PING") != std::string::npos) {
                    std::cout << "RECEIVED PING" << std::endl;
                    serClose(fd);
                    gpioTerminate();
                    return 0;
                }
            }
        }
        gpioDelay(1000);
    }
    std::cerr << "TIMEOUT waiting for PING" << std::endl;
    serClose(fd);
    gpioTerminate();
    return 3;
}
