#!/usr/bin/env python3
"""
DNS Tarpit - Main Entry Point
Orchestrates UDP and TCP tarpit servers with DNS handling
"""
import asyncio
import os
import signal
import sys
import argparse
import logging

from config_loader import load_config, ConfigurationError
from dns_handler import DNSHandler
from udp_tarpit import UDPTarpitServer
from tcp_tarpit import TCPTarpitServer


class DNSTarpitApplication:
    def __init__(self, config_file: str):
        self.config = None
        self.dns_handler = None
        self.udp_server = None
        self.tcp_server = None
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        try:
            self.config = load_config(config_file)
            logger.info(f"Configuration loaded from {config_file}")
        except ConfigurationError as e:
            logger.error(f"Configuration error: {e}")
            raise
        
        self.setup_logging()
        self.dns_handler = DNSHandler(self.config)
        self.udp_server = UDPTarpitServer(self.config, self.dns_handler)
        self.tcp_server = TCPTarpitServer(self.config, self.dns_handler)
    
    def setup_logging(self):
        log_level_str = self.config.get('logging.level', 'INFO')
        log_level = getattr(logging, log_level_str.upper(), logging.INFO)
        
        log_format = self.config.get(
            'logging.format',
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        root_logger.handlers = []
        
        if self.config.get('logging.console', True):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(log_level)
            console_handler.setFormatter(logging.Formatter(log_format))
            root_logger.addHandler(console_handler)
        
        log_file = self.config.get('logging.file')
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(logging.Formatter(log_format))
            root_logger.addHandler(file_handler)
            logger.info(f"Logging to file: {log_file}")
    
    async def start(self):
        logger.info("=" * 60)
        logger.info("DNS Tarpit Starting")
        logger.info("=" * 60)
        logger.info(f"Zone: {self.config.zone}")
        logger.info(f"Listen: {self.config.listen_address}:{self.config.listen_port}")
        logger.info(f"IP Pool: {len(self.config.ip_pool)} addresses")
        logger.info("=" * 60)
        
        self.running = True
        
        if self.config.get('tarpit.udp.enabled', True):
            await self.udp_server.start()
        else:
            logger.info("UDP server disabled")
        if self.config.get('tarpit.tcp.enabled', True):
            await self.tcp_server.start()
        else:
            logger.info("TCP server disabled")
        
        logger.info("All servers started successfully")
    
    async def stop(self):
        if not self.running:
            return
            
        logger.info("Shutting down DNS Tarpit...")
        
        self.running = False
        self.shutdown_event.set()
        if self.udp_server:
            await self.udp_server.stop()
        if self.tcp_server:
            await self.tcp_server.stop()
        
        logger.info("All servers stopped")
    
    async def run(self):
        await self.start()
        
        try:
            await self.shutdown_event.wait()
        except asyncio.CancelledError:
            logger.info("Application cancelled")
        finally:
            await self.stop()


def setup_signal_handlers(app: DNSTarpitApplication):
    def signal_handler(signame):
        logger.info(f"Received signal {signame}, initiating graceful shutdown...")
        app.shutdown_event.set()
    loop = asyncio.get_event_loop()
    for signame in ('SIGINT', 'SIGTERM'):
        loop.add_signal_handler(
            getattr(signal, signame),
            lambda s=signame: signal_handler(s)
        )
    logger.debug("Signal handlers registered")


def check_privileges(port: int):
    if port < 1024 and os.geteuid() != 0:
        logger.warning(
            f"Port {port} requires root privileges. "
            "You may need to run with sudo or set CAP_NET_BIND_SERVICE capability."
        )


def main():
    parser = argparse.ArgumentParser(
        description='DNS Tarpit - Slow DNS server to waste attacker resources',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -c config.yaml              # Run with custom config
  %(prog)s -c config.yaml --debug      # Run with debug logging
  sudo %(prog)s -c config.yaml         # Run as root for port 53

The DNS tarpit acts as an authoritative DNS server but deliberately
responds as slowly as possible to waste attacker resources. UDP queries
are forced to retry over TCP where the real tarpit happens.
        """
    )
    
    parser.add_argument(
        '-c', '--config',
        required=True,
        help='Path to configuration file'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging (overrides config file)'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='DNS Tarpit 2.0'
    )
    
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    global logger
    logger = logging.getLogger(__name__)
    
    try:
        app = DNSTarpitApplication(args.config)
        
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.info("Debug logging enabled via command line")
        
        check_privileges(app.config.listen_port)
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            setup_signal_handlers(app)
            try:
                loop.run_until_complete(app.run())
            except KeyboardInterrupt:
                logger.info("Keyboard interrupt received")
            finally:
                try:
                    pending = asyncio.all_tasks(loop)
                    for task in pending:
                        task.cancel()
                    
                    if pending:
                        loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )
                except Exception as e:
                    logger.debug(f"Error during cleanup: {e}")
                finally:
                    loop.close()
            
        except Exception as e:
            logger.error(f"Fatal error running application: {e}", exc_info=True)
            sys.exit(1)
        
        logger.info("DNS Tarpit shut down complete")
    
    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
