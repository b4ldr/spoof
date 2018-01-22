use Net::RawIP;
my $sock = new Net::RawIP({udp=>{}});
$sock->set({
  ip => {
    saddr => $src_ip,
    daddr => $dst_ip,
    frag_off => 0,
    tos => 0,
    id => 6969,
  },
  udp => {
    source => 6969,
    dest => 53,
    data => $dnsdata,
  }
});
$sock->send;
