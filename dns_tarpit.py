#!/usr/bin/env python3
"""
DNS Tarpit Server

A malicious DNS server that acts as a tarpit by:
1. Redirecting UDP requests to TCP (using truncated responses)
2. Using minimal TCP window sizes to slow down connections
3. Responding with random IP addresses for all queries
4. Deliberately introducing delays to waste attacker resources
"""

import socket
import struct
import random
import threading
import time
import logging
from typing import Tuple
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DNSPacket:
    """Simple DNS packet parser and builder"""

    def __init__(self, data: bytes = None):
        self.transaction_id = 0
        self.flags = 0
        self.questions = 0
        self.answers = 0
        self.authority = 0
        self.additional = 0
        self.query_name = b''
        self.query_type = 0
        self.query_class = 0

        if data:
            self.parse(data)

    def parse(self, data: bytes):
        """Parse DNS packet header"""
        if len(data) < 12:
            return

        # Parse header
        header = struct.unpack('!HHHHHH', data[:12])
        self.transaction_id = header[0]
        self.flags = header[1]
        self.questions = header[2]
        self.answers = header[3]
        self.authority = header[4]
        self.additional = header[5]

        # Parse question section if present
        if self.questions > 0 and len(data) > 12:
            offset = 12
            self.query_name, offset = self._parse_name(data, offset)
            if offset + 4 <= len(data):
                self.query_type, self.query_class = struct.unpack('!HH', data[offset:offset+4])

    def _parse_name(self, data: bytes, offset: int) -> Tuple[bytes, int]:
        """Parse DNS name from packet"""
        name_parts = []
        original_offset = offset
        jumped = False

        while offset < len(data):
            length = data[offset]

            if length == 0:
                offset += 1
                break
            elif length >= 192:  # Compression pointer
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                pointer = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
                offset = pointer
                continue
            else:
                offset += 1
                if offset + length <= len(data):
                    name_parts.append(data[offset:offset+length])
                    offset += length
                else:
                    break

        return b'.'.join(name_parts), original_offset if jumped else offset

    def get_query_domain(self) -> str:
        """Extract the domain name from the query"""
        if not self.query_name:
            return ""

        # Convert bytes to string and normalize
        try:
            domain = self.query_name.decode('ascii').lower().rstrip('.')
            return domain
        except:
            return ""

    def build_truncated_response(self) -> bytes:
        """Build a truncated response to force TCP"""
        # Set response flags: QR=1, TC=1 (truncated)
        response_flags = 0x8200

        response = struct.pack('!HHHHHH',
                             self.transaction_id,
                             response_flags,
                             self.questions,
                             0,  # No answers in truncated response
                             0,  # No authority
                             0   # No additional
                             )

        # Add the original question back
        if self.query_name:
            name_encoded = self._encode_name(self.query_name)
            response += name_encoded
            response += struct.pack('!HH', self.query_type, self.query_class)

        return response

    def build_authoritative_response(self) -> bytes:
        """Build a complete authoritative response with random IP"""
        # Generate random IP address
        random_ip = socket.inet_aton(f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}")

        # Response flags: QR=1, AA=1 (authoritative answer)
        response_flags = 0x8400

        # Header
        response = struct.pack('!HHHHHH',
                             self.transaction_id,
                             response_flags,
                             self.questions,
                             1,  # One answer
                             0,  # No authority
                             0   # No additional
                             )

        # Question section
        if self.query_name:
            name_encoded = self._encode_name(self.query_name)
            response += name_encoded
            response += struct.pack('!HH', self.query_type, self.query_class)

            # Answer section (A record for now)
            if self.query_type == 1:  # A record
                response += name_encoded  # Name (same as question)
                response += struct.pack('!HHIH', 1, 1, 300, 4)  # Type A, Class IN, TTL 300, Length 4
                response += random_ip
            elif self.query_type == 28:  # AAAA record
                # Generate random IPv6 address
                random_ipv6 = bytes([random.randint(0, 255) for _ in range(16)])
                response += name_encoded
                response += struct.pack('!HHIH', 28, 1, 300, 16)  # Type AAAA, Class IN, TTL 300, Length 16
                response += random_ipv6
            else:
                # For other record types, return no answer but authoritative
                # Update header to show 0 answers
                response = struct.pack('!HHHHHH',
                                     self.transaction_id,
                                     response_flags,
                                     self.questions,
                                     0,  # No answers for unsupported types
                                     0,  # No authority
                                     0   # No additional
                                     )
                response += name_encoded
                response += struct.pack('!HH', self.query_type, self.query_class)

        return response

    def build_refused_response(self) -> bytes:
        """Build a REFUSED response for non-authoritative domains"""
        # Response flags: QR=1, RCODE=5 (REFUSED)
        response_flags = 0x8005

        response = struct.pack('!HHHHHH',
                             self.transaction_id,
                             response_flags,
                             self.questions,
                             0,  # No answers
                             0,  # No authority
                             0   # No additional
                             )

        # Add the original question back
        if self.query_name:
            name_encoded = self._encode_name(self.query_name)
            response += name_encoded
            response += struct.pack('!HH', self.query_type, self.query_class)

        return response

    def build_nxdomain_response(self) -> bytes:
        """Build an NXDOMAIN response"""
        # Response flags: QR=1, AA=1, RCODE=3 (NXDOMAIN)
        response_flags = 0x8403

        response = struct.pack('!HHHHHH',
                             self.transaction_id,
                             response_flags,
                             self.questions,
                             0,  # No answers
                             0,  # No authority (could add SOA here)
                             0   # No additional
                             )

        # Add the original question back
        if self.query_name:
            name_encoded = self._encode_name(self.query_name)
            response += name_encoded
            response += struct.pack('!HH', self.query_type, self.query_class)

        return response

    def _encode_name(self, name: bytes) -> bytes:
        """Encode DNS name"""
        if not name:
            return b'\x00'

        parts = name.split(b'.')
        encoded = b''
        for part in parts:
            if len(part) > 63:
                part = part[:63]  # Truncate if too long
            encoded += bytes([len(part)]) + part
        encoded += b'\x00'
        return encoded

class DNSTarpit:
    """DNS Tarpit Server"""

    def __init__(self, host: str = '0.0.0.0', port: int = 53, max_udp_workers: int = 50, max_tcp_connections: int = 100, 
                 authoritative_domains: list = None):
        self.host = host
        self.port = port
        self.running = False
        self.max_udp_workers = max_udp_workers
        self.max_tcp_connections = max_tcp_connections

        # Configure authoritative domains
        self.authoritative_domains = set()
        if authoritative_domains:
            for domain in authoritative_domains:
                # Normalize domain names (lowercase, remove trailing dot)
                normalized = domain.lower().rstrip('.')
                self.authoritative_domains.add(normalized)
                logger.info(f"Configured as authoritative for domain: {normalized}")

        if not self.authoritative_domains:
            logger.warning("No authoritative domains configured - will refuse all queries")

        # Thread pools and connection tracking
        self.udp_executor = ThreadPoolExecutor(max_workers=max_udp_workers, thread_name_prefix="UDP-Worker")
        self.tcp_connections = []
        self.connection_lock = threading.Lock()
        self.connection_count = defaultdict(int)  # Track connections per IP

        # Socket references for cleanup
        self.udp_socket = None
        self.tcp_socket = None

    def is_authoritative_for_domain(self, domain: str) -> bool:
        """Check if this server is authoritative for the given domain"""
        if not domain:
            return False

        domain = domain.lower().rstrip('.')

        # Check exact match
        if domain in self.authoritative_domains:
            return True

        # Check if it's a subdomain of any authoritative domain
        for auth_domain in self.authoritative_domains:
            if domain.endswith('.' + auth_domain) or domain == auth_domain:
                return True

        return False

    def start(self):
        """Start the DNS tarpit server"""
        self.running = True

        # Start UDP server thread
        udp_thread = threading.Thread(target=self._udp_server, daemon=True, name="UDP-Server")
        udp_thread.start()

        # Start TCP server thread  
        tcp_thread = threading.Thread(target=self._tcp_server, daemon=True, name="TCP-Server")
        tcp_thread.start()

        # Start connection monitor thread
        monitor_thread = threading.Thread(target=self._connection_monitor, daemon=True, name="Connection-Monitor")
        monitor_thread.start()

        logger.info(f"DNS Tarpit started on {self.host}:{self.port}")
        logger.info(f"UDP worker pool: {self.max_udp_workers} workers")
        logger.info(f"Max TCP connections: {self.max_tcp_connections}")
        logger.info("UDP requests will be redirected to TCP")
        logger.info("TCP connections will be deliberately slowed")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down DNS Tarpit...")
            self.stop()

    def stop(self):
        """Stop the DNS tarpit server"""
        self.running = False

        # Shutdown thread pool
        logger.info("Shutting down UDP worker pool...")
        self.udp_executor.shutdown(wait=True)

        # Close all TCP connections
        with self.connection_lock:
            logger.info(f"Closing {len(self.tcp_connections)} TCP connections...")
            for conn in self.tcp_connections[:]:
                try:
                    conn.close()
                except:
                    pass
            self.tcp_connections.clear()

        # Close server sockets
        if self.udp_socket:
            try:
                self.udp_socket.close()
            except:
                pass

        if self.tcp_socket:
            try:
                self.tcp_socket.close()
            except:
                pass

        logger.info("DNS Tarpit stopped")

    def _connection_monitor(self):
        """Monitor and log connection statistics"""
        while self.running:
            try:
                time.sleep(30)  # Log stats every 30 seconds
                with self.connection_lock:
                    total_connections = len(self.tcp_connections)
                    unique_ips = len(self.connection_count)

                if total_connections > 0 or unique_ips > 0:
                    logger.info(f"Active TCP connections: {total_connections}, Unique IPs: {unique_ips}")

                    # Log top IPs by connection count
                    if self.connection_count:
                        top_ips = sorted(self.connection_count.items(), key=lambda x: x[1], reverse=True)[:5]
                        logger.info(f"Top IPs by connections: {top_ips}")

            except Exception as e:
                logger.error(f"Connection monitor error: {e}")

    def _udp_server(self):
        """Handle UDP DNS requests - always respond with truncated flag"""
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.settimeout(1.0)  # Allow periodic checks of running flag
            self.udp_socket.bind((self.host, self.port))

            logger.info(f"UDP server listening on {self.host}:{self.port}")

            while self.running:
                try:
                    data, addr = self.udp_socket.recvfrom(512)

                    # Submit UDP request handling to thread pool for concurrent processing
                    future = self.udp_executor.submit(self._handle_udp_request, data, addr)

                    # Don't wait for the result - fire and forget for maximum concurrency

                except socket.timeout:
                    continue
                except OSError:
                    # Socket was likely closed during shutdown
                    if self.running:
                        logger.error("UDP socket error - may have been closed")
                    break
                except Exception as e:
                    if self.running:
                        logger.error(f"UDP server error: {e}")

        except Exception as e:
            logger.error(f"Failed to start UDP server: {e}")

    def _handle_udp_request(self, data: bytes, addr: Tuple[str, int]):
        """Handle individual UDP request in thread pool"""
        try:
            logger.debug(f"Processing UDP query from {addr}")

            # Parse the DNS packet
            dns_packet = DNSPacket(data)
            query_domain = dns_packet.get_query_domain()

            logger.info(f"UDP query for domain '{query_domain}' from {addr[0]}:{addr[1]}")

            # Check if we're authoritative for this domain
            if self.is_authoritative_for_domain(query_domain):
                # Always respond with truncated flag to force TCP for authoritative domains
                response = dns_packet.build_truncated_response()
                response_type = "truncated (forcing TCP)"
            else:
                # For non-authoritative domains, send REFUSED but still slowly
                response = dns_packet.build_refused_response()
                response_type = "REFUSED"

            # Add artificial delay (randomized to prevent predictable timing)
            delay = random.uniform(0.1, 1.0)
            time.sleep(delay)

            # Send response back
            if self.running and self.udp_socket:
                try:
                    self.udp_socket.sendto(response, addr)
                    logger.info(f"Sent {response_type} response to {addr[0]}:{addr[1]} after {delay:.2f}s delay")
                except Exception as e:
                    logger.error(f"Failed to send UDP response to {addr}: {e}")

        except Exception as e:
            logger.error(f"Error handling UDP request from {addr}: {e}")

    def _tcp_server(self):
        """Handle TCP DNS requests - use minimal window and slow responses"""
        try:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_socket.settimeout(1.0)  # Allow periodic checks of running flag

            # Set minimal TCP window size (platform dependent)
            try:
                self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
            except:
                pass  # Some platforms may not support these options

            self.tcp_socket.bind((self.host, self.port))
            self.tcp_socket.listen(50)  # Higher backlog for more concurrent connections

            logger.info(f"TCP server listening on {self.host}:{self.port}")

            while self.running:
                try:
                    client_sock, addr = self.tcp_socket.accept()

                    # Check connection limits
                    with self.connection_lock:
                        # Limit connections per IP
                        ip = addr[0]
                        if self.connection_count[ip] >= 10:  # Max 10 connections per IP
                            logger.warning(f"Connection limit reached for {ip}, dropping new connection")
                            client_sock.close()
                            continue

                        # Limit total connections
                        if len(self.tcp_connections) >= self.max_tcp_connections:
                            logger.warning(f"Max TCP connections ({self.max_tcp_connections}) reached, dropping new connection from {addr}")
                            client_sock.close()
                            continue

                        # Add to tracking
                        self.tcp_connections.append(client_sock)
                        self.connection_count[ip] += 1

                    logger.info(f"TCP connection from {addr} (total: {len(self.tcp_connections)})")

                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self._handle_tcp_client,
                        args=(client_sock, addr),
                        daemon=True,
                        name=f"TCP-Client-{addr[0]}:{addr[1]}"
                    )
                    client_thread.start()

                except socket.timeout:
                    continue
                except OSError:
                    # Socket was likely closed during shutdown
                    if self.running:
                        logger.error("TCP socket error - may have been closed")
                    break
                except Exception as e:
                    if self.running:
                        logger.error(f"TCP server error: {e}")

        except Exception as e:
            logger.error(f"Failed to start TCP server: {e}")

    def _handle_tcp_client(self, client_sock: socket.socket, addr: Tuple[str, int]):
        """Handle individual TCP client connection"""
        ip = addr[0]

        query_count = 0

        try:
            # Set timeouts and minimal TCP window for this connection
            client_sock.settimeout(300)  # 5 minute timeout
            try:
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512)
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512)
                client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            except:
                pass


            # Keep connection alive and handle multiple queries
            while self.running:
                try:
                    # Read length prefix (2 bytes)
                    length_data = client_sock.recv(2)
                    if not length_data:
                        break

                    if len(length_data) < 2:
                        continue

                    query_length = struct.unpack('!H', length_data)[0]

                    # Validate query length (prevent abuse)
                    if query_length > 512 or query_length < 12:
                        logger.warning(f"Invalid query length {query_length} from {addr}")
                        break

                    query_count += 1
                    logger.debug(f"TCP query #{query_count} length: {query_length} from {addr}")

                    # Read the actual query
                    query_data = b''
                    bytes_remaining = query_length

                    while bytes_remaining > 0 and self.running:
                        chunk_size = min(bytes_remaining, random.randint(1, 16))  # Read in small chunks
                        chunk = client_sock.recv(chunk_size)
                        if not chunk:
                            break
                        query_data += chunk
                        bytes_remaining -= len(chunk)

                        # Add small delays while reading to slow down the client
                        time.sleep(random.uniform(0.01, 0.1))

                    if len(query_data) != query_length:
                        logger.warning(f"Incomplete query from {addr}: got {len(query_data)}, expected {query_length}")
                        break

                    # Parse and respond to the query
                    dns_packet = DNSPacket(query_data)
                    query_domain = dns_packet.get_query_domain()

                    logger.info(f"TCP query #{query_count} for domain '{query_domain}' from {ip}")

                    # Generate appropriate response based on domain authority
                    if self.is_authoritative_for_domain(query_domain):
                        response_data = dns_packet.build_authoritative_response()
                        response_type = "authoritative answer"
                    else:
                        # For non-authoritative domains, we can either refuse or return NXDOMAIN
                        # REFUSED is more realistic for an authoritative server
                        response_data = dns_packet.build_refused_response()
                        response_type = "REFUSED"

                    # Add significant artificial delays to waste time
                    delay = random.uniform(2.0, 8.0)  # Even longer delays
                    logger.info(f"TCP query #{query_count} from {ip} - sending {response_type} after {delay:.2f}s delay")
                    time.sleep(delay)

                    if not self.running:
                        break

                    # Send response with length prefix
                    response_length = struct.pack('!H', len(response_data))

                    # Send data in very small chunks to further slow down the connection
                    full_response = response_length + response_data
                    chunk_size = random.randint(1, 4)  # Even smaller chunks

                    bytes_sent = 0
                    for i in range(0, len(full_response), chunk_size):
                        if not self.running:
                            break

                        chunk = full_response[i:i+chunk_size]
                        try:
                            sent = client_sock.send(chunk)
                            bytes_sent += sent

                            # Significant delay between chunks
                            chunk_delay = random.uniform(0.2, 0.8)
                            time.sleep(chunk_delay)
                        except:
                            break

                    logger.info(f"Sent {bytes_sent} bytes to {ip} in {len(full_response)//chunk_size + 1} chunks")

                except socket.timeout:
                    logger.debug(f"Timeout on connection from {addr}")
                    # Don't break - keep the connection alive to waste resources
                    continue
                except ConnectionResetError:
                    logger.info(f"Client {addr} disconnected after {query_count} queries")
                    break
                except Exception as e:
                    logger.error(f"Error handling TCP client {addr}: {e}")
                    break

        except Exception as e:
            logger.error(f"TCP client handler error for {addr}: {e}")
        finally:
            # Clean up connection tracking
            with self.connection_lock:
                try:
                    self.tcp_connections.remove(client_sock)
                except ValueError:
                    pass  # Already removed

                self.connection_count[ip] -= 1
                if self.connection_count[ip] <= 0:
                    del self.connection_count[ip]

            try:
                client_sock.close()
            except:
                pass

            logger.info(f"Closed connection to {addr} after {query_count} queries")

def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='DNS Tarpit Server - Authoritative DNS server that responds slowly')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=53, help='Port to bind to (default: 53)')
    parser.add_argument('--udp-workers', type=int, default=50, help='Maximum UDP worker threads (default: 50)')
    parser.add_argument('--max-connections', type=int, default=100, help='Maximum TCP connections (default: 100)')
    parser.add_argument('--domains', nargs='+', help='Authoritative domains (e.g., --domains example.com test.org)')
    parser.add_argument('--domain-file', help='File containing authoritative domains (one per line)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Parse authoritative domains
    authoritative_domains = []

    if args.domains:
        authoritative_domains.extend(args.domains)

    if args.domain_file:
        try:
            with open(args.domain_file, 'r') as f:
                for line in f:
                    domain = line.strip()
                    if domain and not domain.startswith('#'):
                        authoritative_domains.append(domain)
        except FileNotFoundError:
            logger.error(f"Domain file not found: {args.domain_file}")
            return
        except Exception as e:
            logger.error(f"Error reading domain file: {e}")
            return

    if not authoritative_domains:
        logger.error("No authoritative domains specified. Use --domains or --domain-file")
        logger.error("Example: python dns_tarpit.py --domains example.com test.org")
        return

    # Check if running as root for port 53
    if args.port < 1024:
        import os
        if os.geteuid() != 0:
            logger.warning("Warning: Running on privileged port without root privileges may fail")

    tarpit = DNSTarpit(
        host=args.host, 
        port=args.port,
        max_udp_workers=args.udp_workers,
        max_tcp_connections=args.max_connections,
        authoritative_domains=authoritative_domains
    )

    try:
        tarpit.start()
    except PermissionError:
        logger.error(f"Permission denied: Cannot bind to port {args.port}")
        logger.error("Try running as root or use a port > 1024")
    except Exception as e:
        logger.error(f"Failed to start server: {e}")

if __name__ == '__main__':
    main()
