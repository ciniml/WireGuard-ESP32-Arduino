/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once
#include <IPAddress.h>
#include <stdint.h>

typedef struct {
  IPAddress localIP;
  IPAddress gateway;
  IPAddress subnet;
  const char *privateKey;
  const char *peerHost;
  uint16_t peerPort;
  const char *peerPublickKey;
  struct netif *underlineNetif;
} WireGuardConfig;

class WireGuard
{
private:
    bool _is_initialized = false;
public:
    bool begin(WireGuardConfig *config);
    bool begin(const IPAddress& localIP, const IPAddress& Subnet, const IPAddress& Gateway, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort);
    bool begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort);
    void end();
    bool is_initialized() const { return this->_is_initialized; }
};
