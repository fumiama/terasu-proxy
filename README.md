# terasu-proxy

A transparent proxy that implements TLS record-layer fragmentation in handshakes.

## Background

This project is inspired by [fumiama/terasu](https://github.com/fumiama/terasu) and implements similar functionality as a standalone proxy service.

- **terasu**: A modified TLS library with client-side implementation
- **terasu-proxy**: A transparent proxy that applies the technique **without client modifications**

## Quick Start

### Installation

```bash
go install github.com/Nativu5/terasu-proxy@latest
```

Or build from source:

```bash
git clone https://github.com/Nativu5/terasu-proxy.git
cd terasu-proxy
go build -o terasu-proxy
```

### Serving

```bash
terasu-proxy --listen :15000 --first 3
```

### Proxing

To enable transparent proxing:

```bash
./scripts/setup.sh install
```

To revert:

```bash
./scripts/setup.sh uninstall
```

Check `scripts/setup.sh` for details.
