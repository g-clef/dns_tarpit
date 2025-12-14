# DNS Tarpit - Refactored Version 2.0

A Python-based DNS tarpit server that acts as an authoritative DNS server but deliberately responds as slowly as possible to waste attackers' resources.

## What's New in Version 2.0

This is a complete refactoring of the original DNS tarpit with the following improvements:

### 1. **Modular Architecture**
- Separated DNS protocol logic from tarpit functionality
- UDP and TCP servers in separate, maintainable modules
- Clear separation of concerns

### 2. **Configuration File Support**
- YAML-based configuration
- Define zones, IP ranges, and timing parameters
- No code changes needed for different deployments

### 3. **Leverages Existing Libraries**
- Uses `dnspython` for robust DNS protocol handling
- Asyncio for efficient concurrent connection handling
- Proven, well-tested code for core functionality

## Features

### Core DNS Tarpit Functionality
* **UDP to TCP Redirection**: All UDP DNS queries receive truncated responses, forcing clients to retry over TCP
* **Minimal TCP Windows**: TCP connections use the smallest possible window sizes to slow down data transfer
* **Wildcard Responses**: Responds affirmatively to every DNS query with randomly generated IP addresses
* **Artificial Delays**: Introduces significant delays in responses to waste attackers' time
* **Resource Exhaustion**: Designed to tie up attackers' resources while consuming minimal server resources

### How It Works

1. **UDP Queries**: 
   - Server always responds with the truncated (TC) flag set
   - Forces clients to retry over TCP
   - Minimal delays applied (0.1-0.5 seconds)

2. **TCP Connections**: 
   - Uses minimal TCP buffer sizes (1 byte receive buffer)
   - Introduces random delays (1-5 seconds) before responding
   - Sends data in very small chunks (8 bytes) with delays between chunks (0.5-2 seconds)
   - Keeps connections alive to tie up client resources

3. **DNS Responses**: 
   - Acts as authoritative server for configured zone
   - Responds with random IP addresses for A record queries
   - Proper DNS packet structure to appear legitimate
   - Authoritative answer flag set

## Architecture

```
dns_tarpit/
├── config/
│   └── tarpit_config.yaml     # Configuration file
├── main.py                    # Application entry point
├── config_loader.py           # Configuration parser and validator
├── dns_handler.py             # DNS protocol handling (uses dnspython)
├── tcp_tarpit.py              # TCP tarpit server
├── udp_tarpit.py              # UDP tarpit server
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

### Module Responsibilities

- **main.py**: Orchestrates the application, handles signals, starts servers
- **config_loader.py**: Loads and validates YAML configuration
- **dns_handler.py**: DNS protocol operations using dnspython
- **udp_tarpit.py**: UDP server that forces TCP retry
- **tcp_tarpit.py**: TCP server with slow-send tarpit functionality

## Installation

### Prerequisites

- Python 3.8 or higher
- Root privileges or CAP_NET_BIND_SERVICE capability (for port 53)

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install dnspython>=2.3.0 PyYAML>=6.0
```

## Configuration

Create a YAML configuration file (see `example_config.yaml`):

```yaml
dns:
  zone: "honeypot.example.com"
  listen_address: "0.0.0.0"
  listen_port: 53

ip_responses:
  mode: "pools"
  pools:
    - start: "192.0.2.1"
      end: "192.0.2.254"
  ttl: 300

tarpit:
  udp:
    enabled: true
    always_truncate: true
    delay_range:
      min: 0.1
      max: 0.5
  
  tcp:
    enabled: true
    window_size: 1
    send_buffer: 64
    initial_delay_range:
      min: 1.0
      max: 5.0
    chunk_size: 8
    chunk_delay_range:
      min: 0.5
      max: 2.0

logging:
  level: "INFO"
  file: "/var/log/dns_tarpit.log"
  console: true
```

### Configuration Options

#### DNS Settings
- **zone**: Domain this server is authoritative for
- **listen_address**: Interface to bind to (0.0.0.0 for all)
- **listen_port**: Port to listen on (53 for DNS)

#### IP Response Settings
- **mode**: "pools" or "specific"
- **pools**: List of IP ranges to use for responses
- **specific_ips**: Specific IPs to use (when mode is "specific")
- **ttl**: TTL for DNS records

#### Tarpit Settings

**UDP:**
- **enabled**: Enable/disable UDP server
- **always_truncate**: Always set TC flag
- **delay_range**: Min/max delay before response (seconds)

**TCP:**
- **enabled**: Enable/disable TCP server
- **window_size**: TCP receive buffer size (bytes)
- **send_buffer**: TCP send buffer size (bytes)
- **initial_delay_range**: Delay before starting response (seconds)
- **chunk_size**: Size of each data chunk (bytes)
- **chunk_delay_range**: Delay between chunks (seconds)
- **connection_timeout**: How long to keep connections alive

## Usage

### Basic Usage

```bash
sudo python3 main.py -c config.yaml
```

### With Debug Logging

```bash
sudo python3 main.py -c config.yaml --debug
```

### Using Systemd

Create `/etc/systemd/system/dns-tarpit.service`:

```ini
[Unit]
Description=DNS Tarpit Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/dns_tarpit
ExecStart=/usr/bin/python3 /opt/dns_tarpit/main.py -c /opt/dns_tarpit/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable dns-tarpit
sudo systemctl start dns-tarpit
sudo systemctl status dns-tarpit
```

### Testing

Test with dig (safe for testing):

```bash
# UDP query (will get truncated response)
dig @localhost -p 53 test.honeypot.example.com

# TCP query (will get slow response)
dig @localhost -p 53 +tcp test.honeypot.example.com

# Monitor logs
tail -f /var/log/dns_tarpit.log
```

## Security Considerations

1. **Do not expose to the internet** unless you understand the implications
2. This is a **honeypot/tarpit** tool - it's designed to waste attacker resources
3. Consider rate limiting at the firewall level
4. Monitor resource usage to ensure the tarpit itself isn't overwhelmed
5. Use dedicated hardware/VMs for production deployments

## Monitoring

The application logs:
- All incoming queries (if enabled in config)
- Client IP addresses
- Response times
- Active connection counts

Example log output:
```
2024-01-01 12:00:00 - dns_handler - INFO - Query from 192.0.2.100:12345: test.example.com A
2024-01-01 12:00:00 - tcp_tarpit - INFO - Delaying response to 192.0.2.100 by 3.42s
2024-01-01 12:00:03 - tcp_tarpit - INFO - Sending 150 bytes to 192.0.2.100 in 19 chunks of 8 bytes
```

## Performance Tuning

### For More Aggressive Tarpitting:
- Increase `initial_delay_range.max` (e.g., 30 seconds)
- Decrease `chunk_size` (e.g., 1 byte)
- Increase `chunk_delay_range.max` (e.g., 5 seconds)
- Increase `connection_timeout` (e.g., 3600 seconds)

### For Resource Management:
- Set `max_connections` limits
- Use smaller IP pools
- Adjust log levels to reduce I/O

## Troubleshooting

### "Permission denied" on port 53

Run with sudo or set capabilities:
```bash
sudo setcap cap_net_bind_service=+ep /usr/bin/python3
```

### High memory usage

- Reduce `max_connections`
- Decrease `connection_timeout`
- Check for connection leaks in logs

### Not receiving queries

- Verify firewall rules allow UDP/TCP port 53
- Check the `listen_address` is correct
- Ensure DNS delegation is configured properly

## Development

### Running Tests

```bash
# Test configuration loading
python3 config_loader.py example_config.yaml

# Test DNS handler
python3 dns_handler.py

# Test UDP server
python3 udp_tarpit.py

# Test TCP server
python3 tcp_tarpit.py
```

### Code Structure

Each module is self-contained and can be tested independently:

- `config_loader.py`: Pure configuration logic, no network code
- `dns_handler.py`: DNS protocol only, no network code
- `udp_tarpit.py`: UDP network logic + DNS integration
- `tcp_tarpit.py`: TCP network logic + DNS integration
- `main.py`: Application orchestration

## Migration from Version 1.0

The original single-file implementation has been split into modules:

**Original**: Everything in `dns_tarpit.py`

**Refactored**:
- DNS logic → `dns_handler.py`
- UDP server → `udp_tarpit.py`
- TCP server → `tcp_tarpit.py`
- Configuration → `config_loader.py` + YAML file
- Main loop → `main.py`

To migrate:
1. Create a configuration file based on your current parameters
2. Update any deployment scripts to use `main.py -c config.yaml`
3. Update systemd service files if applicable

## License

Same as original repository license.

## Contributing

When contributing:
1. Maintain separation between modules
2. Add configuration options to YAML, not hardcoded
3. Use logging instead of print statements
4. Write docstrings for new functions/classes
5. Test with various DNS clients

## Credits

- Original implementation: [g-clef/dns_tarpit](https://github.com/g-clef/dns_tarpit)
- DNS library: [dnspython](https://github.com/rthalley/dnspython)
- Tarpit concept: [LaBrea](http://labrea.sourceforge.net/)

## References

- RFC 1035: Domain Names - Implementation and Specification
- RFC 6429: TCP Sender Clarification for Persist Condition
- [Tarpit (networking) - Wikipedia](https://en.wikipedia.org/wiki/Tarpit_(networking))
