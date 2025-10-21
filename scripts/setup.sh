#!/bin/bash

# Variables (can be overridden by environment variables)
MARK=${MARK:-0x1/0x1}
PROXIED_MARK=${PROXIED_MARK:-0x66}
PORT=${PORT:-15001}

# Install function
install() {
    echo "Installing terasu-proxy configuration..."

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1

    # Disable Reverse Path Filtering
    sysctl -w net.ipv4.conf.all.rp_filter=0

    # Flush existing iptables rules
    iptables -t mangle -F

    # Set TPROXY
    iptables -t mangle -A PREROUTING -p tcp --dport 443 -j TPROXY --tproxy-mark $MARK --on-port $PORT

    # Avoid loops
    iptables -t mangle -A OUTPUT -p tcp -m mark --mark $PROXIED_MARK -j RETURN

    # Local OUTPUT redirection
    iptables -t mangle -A OUTPUT -p tcp --dport 443 -j MARK --set-mark $MARK

    # Routes and rules
    ip rule add fwmark $MARK table 100
    ip route add local 0.0.0.0/0 dev lo table 100

    echo "Installation completed successfully."
}

# Uninstall function
uninstall() {
    echo "Uninstalling terasu-proxy configuration..."

    # Remove iptables rules
    iptables -t mangle -D PREROUTING -p tcp --dport 443 -j TPROXY --tproxy-mark $MARK --on-port $PORT 2>/dev/null || true
    iptables -t mangle -D OUTPUT -p tcp -m mark --mark $PROXIED_MARK -j RETURN 2>/dev/null || true
    iptables -t mangle -D OUTPUT -p tcp --dport 443 -j MARK --set-mark $MARK 2>/dev/null || true

    # Remove routes and rules
    ip rule del fwmark $MARK table 100 2>/dev/null || true
    ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true

    echo "Uninstallation completed successfully."
}

# Main script logic
ACTION=${1:-install}

case "$ACTION" in
    install)
        install
        ;;
    uninstall)
        uninstall
        ;;
    *)
        echo "Usage: $0 {install|uninstall}"
        echo ""
        echo "Environment variables:"
        echo "  MARK         - Firewall mark for TPROXY (default: 0x1/0x1)"
        echo "  PROXIED_MARK - Mark for proxied connections (default: 0x66)"
        echo "  PORT         - TPROXY port (default: 15001)"
        echo ""
        echo "Examples:"
        echo "  $0 install                    # Install with defaults"
        echo "  $0 uninstall                  # Uninstall"
        echo "  PORT=15002 $0 install         # Install with custom port"
        exit 1
        ;;
esac
