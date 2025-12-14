"""
UDP Tarpit for DNS
Forces all UDP queries to retry over TCP by setting truncate flag
"""
import asyncio
import random
import logging

logger = logging.getLogger(__name__)


class UDPTarpitServer:
    """
    UDP DNS server that always returns truncated responses
    This forces clients to retry over TCP where the real tarpit happens
    """
    
    def __init__(self, config, dns_handler):
        self.config = config
        self.dns_handler = dns_handler
        self.enabled = config.get('tarpit.udp.enabled', True)
        self.always_truncate = config.get('tarpit.udp.always_truncate', True)
        
        self.listen_address = config.listen_address
        self.listen_port = config.listen_port
        
        self.delay_min = config.get('tarpit.udp.delay_range.min', 0.1)
        self.delay_max = config.get('tarpit.udp.delay_range.max', 0.5)
        
        self.max_connections = config.get('tarpit.udp.max_connections', 1000)
        self.active_connections = 0
        
        self.transport = None
        self.running = False
        
        logger.info(
            f"UDP Tarpit initialized - "
            f"Listen: {self.listen_address}:{self.listen_port}, "
            f"Truncate: {self.always_truncate}, "
            f"Delay: {self.delay_min}-{self.delay_max}s"
        )
    
    async def start(self):
        if not self.enabled:
            logger.info("UDP tarpit is disabled")
            return
        
        logger.info("Starting UDP tarpit server...")
        loop = asyncio.get_event_loop()
        
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDPProtocol(self),
            local_addr=(self.listen_address, self.listen_port)
        )
        
        self.transport = transport
        self.running = True
        
        logger.info(
            f"UDP tarpit listening on {self.listen_address}:{self.listen_port}"
        )
    
    async def stop(self):
        if self.transport:
            self.transport.close()
        self.running = False
        logger.info("UDP tarpit server stopped")
    
    async def handle_query(self, data: bytes, addr: tuple):
        """
        Handle incoming UDP DNS query
        
        Args:
            data: Raw query bytes
            addr: Client address tuple (ip, port)
        """
        if self.active_connections >= self.max_connections:
            logger.warning(
                f"Max connections reached ({self.max_connections}), "
                f"dropping query from {addr[0]}"
            )
            return None
        
        self.active_connections += 1
        
        try:
            query = self.dns_handler.parse_query(data)
            
            if not query:
                logger.warning(f"Invalid query from {addr[0]}")
                return None
            
            self.dns_handler.log_query(query, addr)
            
            if not self.dns_handler.should_respond(query):
                logger.debug(f"Not responding to query from {addr[0]}")
                return None
            
            delay = random.uniform(self.delay_min, self.delay_max)
            logger.debug(f"Delaying UDP response by {delay:.2f}s")
            await asyncio.sleep(delay)

            response = self.dns_handler.build_response(
                query,
                truncate=self.always_truncate
            )
            
            response_data = response.to_wire()
            
            logger.info(
                f"Sending {'truncated' if self.always_truncate else 'normal'} "
                f"UDP response to {addr[0]} ({len(response_data)} bytes)"
            )
            
            return response_data
            
        except Exception as e:
            logger.error(f"Error handling UDP query from {addr[0]}: {e}", exc_info=True)
            return None
            
        finally:
            self.active_connections -= 1


class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: UDPTarpitServer):
        self.server = server
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data: bytes, addr: tuple):
        asyncio.create_task(self._handle_datagram(data, addr))
    
    async def _handle_datagram(self, data: bytes, addr: tuple):
        response_data = await self.server.handle_query(data, addr)
        
        if response_data and self.transport:
            self.transport.sendto(response_data, addr)
    
    def error_received(self, exc):
        logger.error(f"UDP protocol error: {exc}")
    
    def connection_lost(self, exc):
        if exc:
            logger.error(f"UDP connection lost: {exc}")


async def run_udp_server(config, dns_handler):
    server = UDPTarpitServer(config, dns_handler)
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
    
    print("Starting UDP tarpit server...")
    print("Press Ctrl+C to stop")
    print()
    
    try:
        asyncio.run(run_udp_server(config, dns_handler))
    except KeyboardInterrupt:
        print("\nShutting down...")
