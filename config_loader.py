import yaml
import ipaddress
import logging
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    pass


class TarpitConfig:
    def __init__(self, config_dict: Dict[str, Any]):
        self.config = config_dict
        self._ip_pool = None
    
    def get(self, path: str, default: Any = None) -> Any:
        keys = path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    @property
    def zone(self) -> str:
        """Get the DNS zone we're authoritative for"""
        return self.get('dns.zone', 'example.com')
    
    @property
    def listen_address(self) -> str:
        """Get the listen address"""
        return self.get('dns.listen_address', '0.0.0.0')
    
    @property
    def listen_port(self) -> int:
        """Get the listen port"""
        return self.get('dns.listen_port', 53)
    
    @property
    def ip_pool(self) -> List[str]:
        """Get or generate the IP address pool"""
        if self._ip_pool is None:
            self._ip_pool = self._generate_ip_pool()
        return self._ip_pool

    @property
    def cname_subdomain(self) -> str:
        """Get the CNAME loop subdomain name"""
        return self.get('dns.cname_loop.subdomain', '')
    
    def _generate_ip_pool(self) -> List[str]:
        """Generate IP pool from configuration"""
        mode = self.get('ip_responses.mode', 'pools')
        
        if mode == 'specific':
            return self.get('ip_responses.specific_ips', ['192.0.2.1'])
        
        pools = self.get('ip_responses.pools', [])
        ip_list = []
        
        for pool in pools:
            start_ip = ipaddress.IPv4Address(pool['start'])
            end_ip = ipaddress.IPv4Address(pool['end'])
            
            current = start_ip
            while current <= end_ip:
                ip_list.append(str(current))
                current += 1
        
        return ip_list if ip_list else ['192.0.2.1']


def load_config(config_file: str) -> TarpitConfig:
    config_path = Path(config_file)
    
    if not config_path.exists():
        raise ConfigurationError(f"Configuration file not found: {config_file}")
    
    try:
        with open(config_path, 'r') as f:
            config_dict = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in config file: {e}")
    
    if not config_dict:
        raise ConfigurationError("Configuration file is empty")
    
    validate_config(config_dict)
    
    return TarpitConfig(config_dict)


def validate_config(config: Dict[str, Any]) -> None:
    if 'dns' not in config:
        raise ConfigurationError("Missing 'dns' section in configuration")
    
    zone = config.get('dns', {}).get('zone')
    if not zone:
        raise ConfigurationError("DNS zone not specified")
    
    listen_addr = config.get('dns', {}).get('listen_address', '0.0.0.0')
    try:
        ipaddress.ip_address(listen_addr)
    except ValueError:
        raise ConfigurationError(f"Invalid listen address: {listen_addr}")
    
    port = config.get('dns', {}).get('listen_port', 53)
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ConfigurationError(f"Invalid port number: {port}")
    
    if 'ip_responses' in config:
        validate_ip_responses(config['ip_responses'])
    
    if 'tarpit' in config:
        validate_tarpit_config(config['tarpit'])

    if 'cname_loop' in config.get('dns', {}):
        validate_cname_loop_config(config['dns']['cname_loop'])

    logger.info("Configuration validation passed")


def validate_ip_responses(ip_config: Dict[str, Any]) -> None:
    mode = ip_config.get('mode', 'pools')
    
    if mode not in ['pools', 'specific']:
        raise ConfigurationError(f"Invalid IP response mode: {mode}")
    
    if mode == 'pools':
        pools = ip_config.get('pools', [])
        if not pools:
            raise ConfigurationError("No IP pools defined")
        
        for pool in pools:
            if 'start' not in pool or 'end' not in pool:
                raise ConfigurationError("IP pool must have 'start' and 'end'")
            
            try:
                start = ipaddress.IPv4Address(pool['start'])
                end = ipaddress.IPv4Address(pool['end'])
                
                if start > end:
                    raise ConfigurationError(
                        f"Pool start IP {start} is greater than end IP {end}"
                    )
            except ValueError as e:
                raise ConfigurationError(f"Invalid IP address in pool: {e}")
    
    elif mode == 'specific':
        ips = ip_config.get('specific_ips', [])
        if not ips:
            raise ConfigurationError("No specific IPs defined")
        
        for ip in ips:
            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                raise ConfigurationError(f"Invalid IP address: {ip}")


def validate_tarpit_config(tarpit_config: Dict[str, Any]) -> None:
    if 'udp' in tarpit_config:
        udp_config = tarpit_config['udp']
        
        if 'delay_range' in udp_config:
            delay = udp_config['delay_range']
            if delay.get('min', 0) < 0 or delay.get('max', 0) < 0:
                raise ConfigurationError("UDP delays must be non-negative")
            if delay.get('min', 0) > delay.get('max', 1):
                raise ConfigurationError("UDP min delay must be <= max delay")
    
    if 'tcp' in tarpit_config:
        tcp_config = tarpit_config['tcp']
        
        window_size = tcp_config.get('window_size', 1)
        if window_size < 1:
            raise ConfigurationError("TCP window_size must be at least 1")
        
        if 'initial_delay_range' in tcp_config:
            delay = tcp_config['initial_delay_range']
            if delay.get('min', 0) < 0 or delay.get('max', 0) < 0:
                raise ConfigurationError("TCP delays must be non-negative")
            if delay.get('min', 0) > delay.get('max', 1):
                raise ConfigurationError("TCP min delay must be <= max delay")
        
        chunk_size = tcp_config.get('chunk_size', 8)
        if chunk_size < 1:
            raise ConfigurationError("TCP chunk_size must be at least 1")


def validate_cname_loop_config(cname_config: Dict[str, Any]) -> None:
    """Validate CNAME loop configuration"""
    subdomain = cname_config.get('subdomain', '')

    if subdomain:
        # Basic validation that subdomain is a valid DNS label
        if not subdomain.replace('-', '').replace('_', '').isalnum():
            raise ConfigurationError(
                f"Invalid CNAME loop subdomain: {subdomain}"
            )

    ttl = cname_config.get('ttl', 300)
    if not isinstance(ttl, int) or ttl < 0:
        raise ConfigurationError("CNAME loop TTL must be a non-negative integer")


def get_default_config() -> Dict[str, Any]:
    return {
        'dns': {
            'zone': 'example.com',
            'listen_address': '0.0.0.0',
            'listen_port': 53,
            'soa': {
                'primary_ns': 'ns1.example.com',
                'admin_email': 'admin.example.com',
                'serial': 2024010101,
                'refresh': 3600,
                'retry': 600,
                'expire': 86400,
                'minimum': 300
            },
            'cname_loop': {
                'subdomain': 'loop',
                'ttl': 300
            }
        },
        'ip_responses': {
            'mode': 'pools',
            'pools': [
                {'start': '192.0.2.1', 'end': '192.0.2.254'}
            ],
            'ttl': 300
        },
        'tarpit': {
            'udp': {
                'enabled': True,
                'always_truncate': True,
                'delay_range': {'min': 0.1, 'max': 0.5},
                'max_connections': 1000
            },
            'tcp': {
                'enabled': True,
                'window_size': 1,
                'send_buffer': 64,
                'initial_delay_range': {'min': 1.0, 'max': 5.0},
                'chunk_size': 8,
                'chunk_delay_range': {'min': 0.5, 'max': 2.0},
                'connection_timeout': 300,
                'max_connections': 100,
                'nagle_algorithm': True
            }
        },
        'logging': {
            'level': 'INFO',
            'file': None,
            'console': True,
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'log_queries': True,
            'log_client_ips': True
        }
    }


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        try:
            config = load_config(sys.argv[1])
            print("Configuration loaded successfully!")
            print(f"Zone: {config.zone}")
            print(f"Listen: {config.listen_address}:{config.listen_port}")
            print(f"IP Pool size: {len(config.ip_pool)}")
        except ConfigurationError as e:
            print(f"Configuration error: {e}")
            sys.exit(1)
    else:
        print("Usage: python config_loader.py <config_file>")
        print("\nExample default configuration:")
        import pprint
        pprint.pprint(get_default_config())
