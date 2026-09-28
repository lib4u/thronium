// Generated from engine defaults; change them in Rust.
export const defaults = {
  "dynamicPool": {
    "buildLimit": 300,
    "poolCap": 1000
  },
  "geodataProviders": [
    {
      "geoip": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat",
      "geosite": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat",
      "id": "global",
      "name": "Loyalsoldier (global / China)"
    },
    {
      "geoip": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat",
      "geosite": "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat",
      "id": "ru",
      "name": "runetfreedom (Russia)"
    },
    {
      "geoip": "https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/geoip.dat",
      "geosite": "https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/geosite.dat",
      "id": "ir",
      "name": "Chocolate4U (Iran)"
    },
    {
      "geoip": "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
      "geosite": "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
      "id": "v2fly",
      "name": "v2fly (upstream)"
    }
  ],
  "groups": [
    {
      "id": "personal",
      "name": "Personal"
    }
  ],
  "otp": {
    "algorithm": "SHA1",
    "counter": "0",
    "digits": 6,
    "issuer": "",
    "name": "",
    "period": 30,
    "secret": "",
    "type": "totp"
  },
  "personalGroup": "personal",
  "poolProfile": {
    "active_size": 8,
    "bench_interval": "600s",
    "concurrency": 12,
    "dial_retries": 2,
    "expected": 3,
    "interrupt_exist_connections": true,
    "interval": "120s",
    "members": [],
    "reuse_ttl": "30m",
    "sampling": 10,
    "timeout": "5s",
    "tolerance": 100,
    "type": "auto-selector",
    "url": "https://www.gstatic.com/generate_204",
    "watch_interval": "15s"
  },
  "preferences": {
    "autoSelect": {
      "config": {
        "bench_interval": "600s",
        "concurrency": 12,
        "dial_retries": 2,
        "interval": "120s",
        "reuse_ttl": "30m",
        "timeout": "5s",
        "tolerance": 100,
        "url": "https://www.gstatic.com/generate_204",
        "watch_interval": "15s"
      },
      "enabled": true,
      "failover": true,
      "sourceGroupId": null
    },
    "closeBehavior": "quit",
    "connectionMode": "local",
    "inboundPort": 2080,
    "language": "ru",
    "librarySort": "original",
    "librarySortDescending": false,
    "ping": {
      "method": "auto",
      "timeoutMs": 3000,
      "url": "https://www.gstatic.com/generate_204"
    },
    "theme": "light",
    "tun": {
      "autoReconnect": true,
      "dnsHijack": true,
      "excludeAddresses": [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8"
      ],
      "ipv6": false,
      "mtu": 1500,
      "requestPermission": true,
      "stack": "gvisor",
      "strictRoute": false,
      "systemDns": "disabled"
    },
    "vlessCore": "xray",
    "vlessOverrides": {}
  },
  "routing": {
    "active": "default",
    "mode": "rules",
    "name": "Default"
  },
  "routingProfile": {
    "dns": {
      "final": "dns-direct",
      "servers": [
        {
          "tag": "dns-direct",
          "type": "local"
        }
      ]
    },
    "id": "default",
    "mode": "rules",
    "name": "Default",
    "route": {
      "auto_detect_interface": true,
      "default_domain_resolver": "dns-direct",
      "final": "proxy",
      "find_process": true
    },
    "rules": []
  },
  "testUrl": "https://www.gstatic.com/generate_204"
} as const;
