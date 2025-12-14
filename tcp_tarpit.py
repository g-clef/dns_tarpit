import socket
import asyncio
import random
import struct
import logging

logger = logging.getLogger(__name__)


class TCPTarpitServer:
    """
    TCP DNS server that deliberately responds as slowly as possible
    Uses minimal TCP window sizes and chunked sending to tarpit attackers
    """
    def __init__(self, config, dns_handler):
        self.config = config
        self.dns_handler = dns_handler
        self.enabled = config.get('tarpit.tcp.enabled', True)
        
        self.listen_address = config.listen_address
        self.listen_port = config.listen_port
        
        self.window_size = config.get('tarpit.tcp.window_size', 1)
        self.send_buffer = config.get('tarpit.tcp.send_buffer', 64)
        
        self.initial_delay_min = config.get('tarpit.tcp.initial_delay_range.min', 1.0)
        self.initial_delay_max = config.get('tarpit.tcp.initial_delay_range.max', 5.0)
        
        self.chunk_size = config.get('tarpit.tcp.chunk_size', 8)
        self.chunk_delay_min = config.get('tarpit.tcp.chunk_delay_range.min', 0.5)
        self.chunk_delay_max = config.get('tarpit.tcp.chunk_delay_range.max', 2.0)
        
        self.connection_timeout = config.get('tarpit.tcp.connection_timeout', 300)
        self.max_connections = config.get('tarpit.tcp.max_connections', 100)
        self.nagle_algorithm = config.get('tarpit.tcp.nagle_algorithm', True)
        
        self.active_connections = 0
        self.server = None
        self.running = False
        
        logger.info(
            f"TCP Tarpit initialized - "
            f"Listen: {self.listen_address}:{self.listen_port}, "
            f"Window: {self.window_size}B, "
            f"Chunk: {self.chunk_size}B, "
            f"Delay: {self.initial_delay_min}-{self.initial_delay_max}s"
        )
    
    async def start(self):
        if not self.enabled:
            logger.info("TCP tarpit is disabled")
            return
        
        logger.info("Starting TCP tarpit server...")
        self.server = await asyncio.start_server(
            self.handle_client,
            self.listen_address,
            self.listen_port,
            reuse_address=True,
            reuse_port=True
        )
        
        self.running = True
        
        addr = self.server.sockets[0].getsockname()
        logger.info(f"TCP tarpit listening on {addr[0]}:{addr[1]}")
        asyncio.create_task(self._serve())
    
    async def _serve(self):
        if self.server:
            async with self.server:
                await self.server.serve_forever()
    
    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.running = False
        logger.info("TCP tarpit server stopped")
    
    def configure_socket(self, sock: socket.socket):
        try:
            # Set minimal receive buffer (TCP window)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.window_size)
            
            # Set minimal send buffer
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.send_buffer)
            
            # Configure Nagle's algorithm
            # When enabled (TCP_NODELAY=0), small packets are batched
            # This further slows down transmission
            if not self.nagle_algorithm:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            else:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            logger.debug(
                f"Socket configured: RCVBUF={self.window_size}, "
                f"SNDBUF={self.send_buffer}, "
                f"TCP_NODELAY={not self.nagle_algorithm}"
            )
            
        except Exception as e:
            logger.error(f"Error configuring socket: {e}")
    
    async def handle_client(self,
                            reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter):

        addr = writer.get_extra_info('peername')
        logger.info(f"New TCP connection from {addr[0]}:{addr[1]}")
        
        if self.active_connections >= self.max_connections:
            logger.warning(
                f"Max connections reached ({self.max_connections}), "
                f"rejecting {addr[0]}"
            )
            writer.close()
            await writer.wait_closed()
            return
        
        self.active_connections += 1
        
        try:
            sock = writer.get_extra_info('socket')
            if sock:
                self.configure_socket(sock)
            
            initial_delay = random.uniform(
                self.initial_delay_min,
                self.initial_delay_max
            )
            logger.info(
                f"Delaying response to {addr[0]} by {initial_delay:.2f}s"
            )
            await asyncio.sleep(initial_delay)
            timeout = self.connection_timeout if self.connection_timeout > 0 else None
            
            try:
                length_data = await asyncio.wait_for(
                    reader.readexactly(2),
                    timeout=timeout
                )
                query_length = struct.unpack('!H', length_data)[0]
                logger.debug(f"Expecting {query_length} bytes from {addr[0]}")
                query_data = await asyncio.wait_for(
                    reader.readexactly(query_length),
                    timeout=timeout
                )
                query = self.dns_handler.parse_query(query_data)
                
                if not query:
                    logger.warning(f"Invalid query from {addr[0]}")
                    return
                
                self.dns_handler.log_query(query, addr)
                if not self.dns_handler.should_respond(query):
                    logger.debug(f"Not responding to query from {addr[0]}")
                    return
                
                response = self.dns_handler.build_response(query, truncate=False)
                response_data = response.to_wire()
                await self.slow_send(writer, response_data, addr)
                
                logger.info(
                    f"Completed slow send to {addr[0]} "
                    f"({len(response_data)} bytes)"
                )
            except asyncio.TimeoutError:
                logger.info(f"Connection to {addr[0]} timed out during read")
            except asyncio.IncompleteReadError:
                logger.info(f"Client {addr[0]} disconnected during read")
            except ConnectionResetError:
                logger.info(f"Client {addr[0]} reset connection (gave up waiting)")
            except BrokenPipeError:
                logger.info(f"Client {addr[0]} closed connection (broken pipe)")
            
        except ConnectionResetError:
            logger.info(f"Client {addr[0]} reset connection before query")
        except BrokenPipeError:
            logger.info(f"Client {addr[0]} closed connection before query")
        except Exception as e:
            logger.error(
                f"Unexpected error handling connection from {addr[0]}: {e}",
                exc_info=True
            )
            
        finally:
            self.active_connections -= 1
            
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            
            logger.info(
                f"Connection closed from {addr[0]} "
                f"({self.active_connections} active)"
            )
    
    async def slow_send(self, writer: asyncio.StreamWriter, 
                       data: bytes, addr: tuple):
        """
        Send data very slowly in small chunks with delays
        
        Args:
            writer: StreamWriter to send data through
            data: Data to send
            addr: Client address for logging
        """
        length_prefix = struct.pack('!H', len(data))
        full_data = length_prefix + data
        
        total_chunks = (len(full_data) + self.chunk_size - 1) // self.chunk_size
        
        logger.info(
            f"Sending {len(full_data)} bytes to {addr[0]} "
            f"in {total_chunks} chunks of {self.chunk_size} bytes"
        )

        bytes_sent = 0
        try:
            for i in range(0, len(full_data), self.chunk_size):
                chunk = full_data[i:i + self.chunk_size]
                
                writer.write(chunk)
                await writer.drain()
                
                bytes_sent = i + len(chunk)
                
                chunk_num = i // self.chunk_size + 1
                logger.debug(
                    f"Sent chunk {chunk_num}/{total_chunks} "
                    f"({len(chunk)} bytes) to {addr[0]}"
                )
                
                if i + self.chunk_size < len(full_data):
                    delay = random.uniform(
                        self.chunk_delay_min,
                        self.chunk_delay_max
                    )
                    await asyncio.sleep(delay)
        
        except (ConnectionResetError, BrokenPipeError) as e:
            # Client gave up - this is actually a success
            logger.info(
                f"Client {addr[0]} disconnected during slow send "
                f"after {bytes_sent}/{len(full_data)} bytes - client gave up"
            )
            raise
        except Exception as e:
            logger.error(f"Error during slow send to {addr[0]}: {e}")
            raise


async def run_tcp_server(config, dns_handler):
    server = TCPTarpitServer(config, dns_handler)
    await server.start()
    
    try:
        while server.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    finally:
        await server.stop()


if __name__ == '__main__':
    from config_loader import get_default_config, TarpitConfig
    from dns_handler import DNSHandler
    
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    config = TarpitConfig(get_default_config())
    dns_handler = DNSHandler(config)
    
    print("Starting TCP tarpit server...")
    print("Press Ctrl+C to stop")
    print()
    
    try:
        asyncio.run(run_tcp_server(config, dns_handler))
    except KeyboardInterrupt:
        print("\nShutting down...")
