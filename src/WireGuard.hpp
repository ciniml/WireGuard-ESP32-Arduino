#pragma once
#include <IPAddress.h>

class WireGuard
{
public:
    void begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort);
};
