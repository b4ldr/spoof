import scapy
import dns.message
import dns.rdatatype
import dns.rdataclass
query = dns.message.make_query(qname, dns.rdatatype.SOA, dns.rdataclass.IN)
query.use_edns(payload=4096, options=[dns.edns.GenericOption(dns.edns.NSID, '')])
send(IP(src=src, dst=dst)/UDP(sport=src_port,dport=dst_port)/Raw(load=query.to_wire()))

