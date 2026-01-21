"""
DNS Handler for DNS Tarpit
Handles DNS protocol using dnspython library
"""
import random
import logging
from typing import Optional

import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.flags
import dns.rrset
import dns.rdtypes.IN.A
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.CNAME
import dns.name

logger = logging.getLogger(__name__)


class DNSHandler:
    """
    Handles DNS protocol operations
    Uses dnspython for DNS message parsing and construction
    """
    
    def __init__(self, config):
        """
        Initialize DNS handler with configuration
        
        Args:
            config: TarpitConfig object
        """
        self.config = config
        self.zone = dns.name.from_text(config.zone)
        self.ip_pool = config.ip_pool
        
        self._soa_record = None
        
        logger.info(f"DNS Handler initialized for zone: {config.zone}")
        logger.info(f"IP pool contains {len(self.ip_pool)} addresses")
    
    def parse_query(self, data: bytes) -> Optional[dns.message.Message]:
        """
        Parse incoming DNS query from wire format
        
        Args:
            data: Raw DNS query bytes
            
        Returns:
            Parsed DNS message or None if invalid
        """
        try:
            query = dns.message.from_wire(data)
            
            if len(query.question) == 0:
                logger.warning("Received query with no questions")
                return None
            
            return query
            
        except Exception as e:
            logger.error(f"Failed to parse DNS query: {e}")
            return None
    
    def should_respond(self, query: dns.message.Message) -> bool:
        """
        Check if we should respond to this query
        
        Args:
            query: Parsed DNS query message
            
        Returns:
            True if we should respond (query is for our zone)
        """
        if not query.question:
            return False
        
        qname = query.question[0].name
        
        # Check if query is for our zone or a subdomain
        # We're a wildcard authoritative server, so we respond to everything
        # in our zone
        try:
            is_subdomain = qname.is_subdomain(self.zone) or qname == self.zone
            
            if is_subdomain:
                logger.debug(f"Query for {qname} matches our zone {self.zone}")
            
            return is_subdomain
            
        except Exception as e:
            logger.error(f"Error checking zone match: {e}")
            return False
    
    def get_random_ip(self) -> str:
        """
        Get a random IP address from the configured pool

        Returns:
            Random IP address as string
        """
        return random.choice(self.ip_pool)

    def is_cname_loop_query(self, qname: dns.name.Name) -> bool:
        """
        Check if this query is for the CNAME loop subdomain

        Args:
            qname: The query name

        Returns:
            True if query is for CNAME loop subdomain
        """
        cname_subdomain = self.config.cname_subdomain

        if not cname_subdomain:
            return False

        # Build the full CNAME subdomain name
        cname_zone = dns.name.from_text(f"{cname_subdomain}.{self.config.zone}")

        # Check if query is for this subdomain or any name under it
        return qname.is_subdomain(cname_zone) or qname == cname_zone

    def generate_random_cname_target(self, qname: dns.name.Name) -> dns.name.Name:
        """
        Generate a random CNAME target within the CNAME loop subdomain

        Args:
            qname: The original query name

        Returns:
            A random name within the CNAME loop subdomain
        """
        cname_subdomain = self.config.cname_subdomain

        # Generate a random label (8-16 characters)
        import string
        length = random.randint(8, 16)
        random_label = ''.join(
            random.choices(string.ascii_lowercase + string.digits, k=length)
        )

        # Build the target name: <random>.<cname_subdomain>.<zone>
        target = f"{random_label}.{cname_subdomain}.{self.config.zone}"
        return dns.name.from_text(target)

    def build_response(self, 
                      query: dns.message.Message,
                      truncate: bool = False) -> dns.message.Message:
        """
        Build DNS response for a query
        
        Args:
            query: The DNS query message
            truncate: If True, set TC flag (for UDP tarpit)
            
        Returns:
            DNS response message
        """
        response = dns.message.make_response(query)

        response.flags |= dns.flags.AA
        
        if truncate:
            response.flags |= dns.flags.TC
            logger.debug(f"Setting TC flag for query {query.question[0].name}")
            return response
        
        question = query.question[0]
        qname = question.name
        qtype = question.rdtype

        # Check if this is a query for the CNAME loop subdomain
        if self.is_cname_loop_query(qname):
            # For A and AAAA queries, return CNAME instead
            if qtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                self._add_cname_record(response, qname)
                logger.info(f"Responding to {qname} ({dns.rdatatype.to_text(qtype)}) with CNAME loop")
                return response
            # For other query types, fall through to normal handling

        if qtype == dns.rdatatype.A:
            self._add_a_record(response, qname)
        elif qtype == dns.rdatatype.NS:
            self._add_ns_record(response, qname)
        elif qtype == dns.rdatatype.SOA:
            self._add_soa_record(response, qname)
        elif qtype == dns.rdatatype.ANY:
            # For ANY queries, return A, NS, and SOA
            self._add_a_record(response, qname)
            self._add_ns_record(response, qname)
            self._add_soa_record(response, qname)
        else:
            # For other record types, return NOERROR with no answer
            # (authoritative server doesn't have this type)
            logger.debug(f"No handler for query type {dns.rdatatype.to_text(qtype)}")
        
        return response
    
    def _add_a_record(self, response: dns.message.Message, qname: dns.name.Name):
        """Add A record to response with random IP"""
        ttl = self.config.get('ip_responses.ttl', 300)
        ip_address = self.get_random_ip()
        
        rrset = response.find_rrset(
            response.answer,
            qname,
            dns.rdataclass.IN,
            dns.rdatatype.A,
            create=True
        )
        
        rdata = dns.rdtypes.IN.A.A(
            dns.rdataclass.IN,
            dns.rdatatype.A,
            ip_address
        )
        
        rrset.add(rdata, ttl=ttl)

        logger.info(f"Responding to {qname} with A record: {ip_address}")

    def _add_cname_record(self, response: dns.message.Message, qname: dns.name.Name):
        """Add CNAME record to response pointing to random name in same subdomain"""
        ttl = self.config.get('dns.cname_loop.ttl', 300)

        # Generate a random target within the CNAME loop subdomain
        target = self.generate_random_cname_target(qname)

        rrset = response.find_rrset(
            response.answer,
            qname,
            dns.rdataclass.IN,
            dns.rdatatype.CNAME,
            create=True
        )

        rdata = dns.rdtypes.ANY.CNAME.CNAME(
            dns.rdataclass.IN,
            dns.rdatatype.CNAME,
            target
        )

        rrset.add(rdata, ttl=ttl)

        logger.debug(f"Added CNAME record for {qname} -> {target}")

    def _add_ns_record(self, response: dns.message.Message, qname: dns.name.Name):
        """Add NS record to response"""
        ttl = self.config.get('ip_responses.ttl', 300)
        
        ns_name = self.config.get('dns.soa.primary_ns', f'ns1.{self.config.zone}')
        ns_name_obj = dns.name.from_text(ns_name)
        
        rrset = response.find_rrset(
            response.answer,
            qname,
            dns.rdataclass.IN,
            dns.rdatatype.NS,
            create=True
        )
        
        rdata = dns.rdtypes.ANY.NS.NS(
            dns.rdataclass.IN,
            dns.rdatatype.NS,
            ns_name_obj
        )
        
        rrset.add(rdata, ttl=ttl)
        
        logger.debug(f"Added NS record for {qname}: {ns_name}")
    
    def _add_soa_record(self, response: dns.message.Message, qname: dns.name.Name):
        """Add SOA record to response"""
        ttl = self.config.get('ip_responses.ttl', 300)
        
        soa_config = self.config.get('dns.soa', {})
        
        mname = dns.name.from_text(
            soa_config.get('primary_ns', f'ns1.{self.config.zone}')
        )
        rname = dns.name.from_text(
            soa_config.get('admin_email', f'admin.{self.config.zone}')
        )
        
        rrset = response.find_rrset(
            response.answer,
            qname,
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            create=True
        )
        
        rdata = dns.rdtypes.ANY.SOA.SOA(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            mname=mname,
            rname=rname,
            serial=soa_config.get('serial', 2024010101),
            refresh=soa_config.get('refresh', 3600),
            retry=soa_config.get('retry', 600),
            expire=soa_config.get('expire', 86400),
            minimum=soa_config.get('minimum', 300)
        )
        
        rrset.add(rdata, ttl=ttl)
        
        logger.debug(f"Added SOA record for {qname}")
    
    def build_error_response(self, 
                             query: dns.message.Message,
                             rcode: int = dns.rcode.SERVFAIL) -> dns.message.Message:
        """
        Build an error response
        
        Args:
            query: The DNS query message
            rcode: Response code (default: SERVFAIL)
            
        Returns:
            DNS error response message
        """
        response = dns.message.make_response(query)
        response.set_rcode(rcode)
        
        logger.debug(f"Building error response with rcode: {dns.rcode.to_text(rcode)}")
        
        return response
    
    def log_query(self, query: dns.message.Message, client_addr: tuple):
        """
        Log details about a DNS query
        
        Args:
            query: The DNS query message
            client_addr: Tuple of (ip, port)
        """
        if not self.config.get('logging.log_queries', True):
            return
        
        if not query.question:
            return
        
        question = query.question[0]
        qname = question.name
        qtype = dns.rdatatype.to_text(question.rdtype)
        
        if self.config.get('logging.log_client_ips', True):
            logger.info(
                f"Query from {client_addr[0]}:{client_addr[1]}: "
                f"{qname} {qtype}"
            )
        else:
            logger.info(f"Query: {qname} {qtype}")


if __name__ == '__main__':
    from config_loader import get_default_config, TarpitConfig
    
    config = TarpitConfig(get_default_config())
    handler = DNSHandler(config)
    
    test_query = dns.message.make_query('test.example.com', dns.rdatatype.A)
    
    print("Test Query:")
    print(test_query)
    print()
    
    if handler.should_respond(test_query):
        response = handler.build_response(test_query)
        print("Test Response (non-truncated):")
        print(response)
        print()
        
        truncated_response = handler.build_response(test_query, truncate=True)
        print("Test Response (truncated):")
        print(truncated_response)
    else:
        print("Handler would not respond to this query")
