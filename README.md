# DNS Tarpit

A Python-based DNS tarpit server that acts as an authoritative DNS server but deliberately responds as slowly as possible to waste attackers' resources.

## Features

- **UDP to TCP Redirection**: All UDP DNS queries receive truncated responses, forcing clients to retry over TCP
- **Minimal TCP Windows**: TCP connections use the smallest possible window sizes to slow down data transfer
- **Wildcard Responses**: Responds affirmatively to every DNS query with randomly generated IP addresses
- **Artificial Delays**: Introduces significant delays in responses to waste attackers' time
- **Resource Exhaustion**: Designed to tie up attackers' resources while consuming minimal server resources

## How it Works

1. **UDP Queries**: The server always responds to UDP queries with the truncated (TC) flag set, forcing clients to retry over TCP
2. **TCP Connections**: When clients connect via TCP, the server:
   - Uses minimal TCP buffer sizes
   - Introduces random delays (1-5 seconds) before responding
   - Sends data in very small chunks with delays between chunks
   - Keeps connections alive to tie up client resources
3. **DNS Responses**: For all queries, the server acts as an authoritative server and responds with:
   - Random IP addresses for A record queries
   - Proper DNS packet structure to appear legitimate
   - Authoritative answer flag set

## Installation

1. Clone the repository: