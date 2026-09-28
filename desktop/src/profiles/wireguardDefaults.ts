/** A peer's allowed IPs when a source does not list them: all IPv4 and IPv6 traffic. */
export const allTraffic = (): string[] => ['0.0.0.0/0', '::/0'];
/** The standard WireGuard listening port, offered for a new peer. */
export const WIREGUARD_PORT = 51820;
