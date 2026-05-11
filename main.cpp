#include <iostream>

extern void runOtaService();

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "   RPi OTA Manager (HTTP + MQTT Mode)   " << std::endl;
    std::cout << "========================================" << std::endl;

    runOtaService();

    return 0;
}
