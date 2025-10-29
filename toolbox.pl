#!/usr/bin/env perl
use strict;
use warnings;
use IO::Socket::INET;
use Socket qw(getaddrinfo getnameinfo NI_NUMERICHOST AF_UNSPEC SOCK_STREAM);
use POSIX qw(strftime);

# ---------------------------------------
# Helper utilities
# ---------------------------------------
sub ts { strftime("%Y-%m-%d %H:%M:%S", localtime) }

sub die_usage {
    print <<"USAGE";
Perl Net/Audit Toolbox  (no non-core deps)

Usage:
  perl toolbox.pl ifaces
  perl toolbox.pl routes
  perl toolbox.pl arp
  perl toolbox.pl sockets [tcp|udp]
  perl toolbox.pl resolv
  perl toolbox.pl dns <host>
  perl toolbox.pl tcp <host> <port> [timeoutSec]
  perl toolbox.pl http-head <host> [port]
  perl toolbox.pl http-get <host> [port] [path]
  perl toolbox.pl ping-tcp <host> [port=80] [timeoutSec=2]
  perl toolbox.pl traceroute-tcp <host> [port=80] [maxHops=20] [timeoutSec=2]
  perl toolbox.pl whoami

Notes:
- Works inside minimal containers; NetworkPolicies still apply.
- No CAP_NET_RAW needed (we use TCP connects instead of ICMP).
- traceroute-tcp may be blocked by policies/runtime and just show "*".
USAGE
    exit 1;
}

sub hextoip {
    my ($h) = @_;
    return "0.0.0.0" unless defined $h && $h =~ /^[0-9A-Fa-f]{8}$/;
    my @b = ($h =~ /(..)(..)(..)(..)/);
    return join '.', map { hex $_ } reverse @b;
}

my %TCP_STATE = (
  '01'=>'ESTABLISHED','02'=>'SYN_SENT','03'=>'SYN_RECV','04'=>'FIN_WAIT1','05'=>'FIN_WAIT2',
  '06'=>'TIME_WAIT','07'=>'CLOSE','08'=>'CLOSE_WAIT','09'=>'LAST_ACK','0A'=>'LISTEN','0B'=>'CLOSING'
);

# ---------------------------------------
# Commands
# ---------------------------------------
sub cmd_ifaces {
    print "[",ts,"] Interfaces\n";
    my $path = "/sys/class/net";
    opendir(my $d,$path) or die "Cannot open $path: $!";
    my @ifs = sort grep { !/^\./ } readdir($d);
    closedir $d;
    for my $if (@ifs) {
        my $oper = do {
    my $f = "$path/$if/operstate";
    my $v = "unknown";
    if (open(my $fh, '<', $f)) {
        my $line = <$fh>;
        if (defined $line) { chomp $line; $v = $line; }
        close $fh;
    }
    $v;
};

        print sprintf("  %-12s state=%s\n",$if,$oper);
    }
}

sub cmd_routes {
    print "[",ts,"] Routes (/proc/net/route)\n";
    open my $fh,'<','/proc/net/route' or die "Cannot read /proc/net/route: $!";
    my $hdr = <$fh>;
    print "IFACE        DEST           GATEWAY        MASK           FLAGS\n";
    while (<$fh>) {
        chomp; my @f=split;
        next unless @f>=8;
        my ($iface,$dst,$gw,$flags,$mask)=($f[0],hextoip($f[1]),hextoip($f[2]),$f[3],hextoip($f[7]));
        printf "%-12s %-14s %-14s %-14s 0x%s\n",$iface,$dst,$gw,$mask,$flags;
    }
    close $fh;
}

sub cmd_arp {
    print "[",ts,"] ARP cache (/proc/net/arp)\n";
    open my $fh,'<','/proc/net/arp' or die "Cannot read /proc/net/arp: $!";
    my $hdr = <$fh>;
    print "IP              HWTYPE  FLAGS  MAC               IFACE\n";
    while (<$fh>) {
        chomp; my @F=split;
        printf "%-15s  %-6s  %-5s  %-17s  %s\n", $F[0],$F[1],$F[2],$F[3],$F[5];
    }
    close $fh;
}

sub parse_proc_net {
    my ($file,$proto) = @_;
    open my $fh,'<',$file or die "Cannot read $file: $!";
    my $hdr = <$fh>;
    my @rows;
    while (<$fh>) {
        chomp; my @f=split;
        my ($l,$r,$st) = @f[1,2,3];
        my ($lip,$lp) = split /:/, $l;
        my ($rip,$rp) = split /:/, $r;
        my $lip_s = hextoip($lip);
        my $rip_s = hextoip($rip);
        my $lp_n  = hex $lp;
        my $rp_n  = hex $rp;
        my $state = $TCP_STATE{uc($st)} // $st;
        push @rows, [$proto, $lip_s,$lp_n, $rip_s,$rp_n, $state];
    }
    close $fh;
    return @rows;
}

sub cmd_sockets {
    my ($which) = @_;
    $which ||= 'tcp';
    print "[",ts,"] Active sockets ($which)\n";
    my @rows;
    if ($which =~ /^tcp$/i) { push @rows, parse_proc_net('/proc/net/tcp','tcp') }
    if ($which =~ /^udp$/i) { push @rows, parse_proc_net('/proc/net/udp','udp') }
    printf "%-4s %-21s -> %-21s %-12s\n","PROT","LOCAL","REMOTE","STATE";
    for my $r (@rows) {
        printf "%-4s %-21s -> %-21s %-12s\n",
            $r->[0], "$r->[1]:$r->[2]", "$r->[3]:$r->[4]", $r->[5];
    }
}

sub cmd_resolv {
    print "[",ts,"] /etc/resolv.conf\n";
    if (open my $fh,'<','/etc/resolv.conf') {
        while (<$fh>) { print }
        close $fh;
    } else {
        print "Cannot read /etc/resolv.conf: $!\n";
    }
}

sub cmd_dns {
    my ($host) = @_;
    $host or die_usage();
    print "[",ts,"] DNS resolve: $host\n";
    my @res = getaddrinfo($host, undef, { family=>AF_UNSPEC, socktype=>SOCK_STREAM });
    my $found=0;
    while (@res) {
        my ($ai,@rest) = @res;
        last unless $ai;
        my ($num) = getnameinfo($ai->{addr}, NI_NUMERICHOST);
        print "  $num\n";
        $found=1;
        @res = @rest;
    }
    print "  (no records)\n" unless $found;
}

sub cmd_tcp {
    my ($host,$port,$to) = @_;
    $host && $port or die_usage();
    $to ||= 3;
    print "[",ts,"] TCP connect test $host:$port (timeout ${to}s)\n";
    $|=1;
    my $ok;
    eval {
        local $SIG{ALRM}=sub{ die "timeout\n" }; alarm $to;
        my $s = IO::Socket::INET->new(PeerAddr=>$host, PeerPort=>$port, Proto=>'tcp')
            or die "$!";
        $ok=1; close $s; alarm 0;
    };
    if ($ok) { print "  OPEN\n" } else { print "  CLOSED: $@\n" }
}

sub cmd_http_head {
    my ($host,$port) = @_;
    $host or die_usage();
    $port ||= 80;
    print "[",ts,"] HTTP HEAD http://$host:$port/\n";
    my $s = IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Proto=>'tcp',Timeout=>5)
        or die " connect fail: $!";
    print $s "HEAD / HTTP/1.0\r\nHost: $host\r\n\r\n";
    while (<$s>) { print }
    close $s;
}

sub cmd_http_get {
    my ($host,$port,$path) = @_;
    $host or die_usage();
    $port ||= 80; $path ||= "/";
    print "[",ts,"] HTTP GET http://$host:$port$path\n";
    my $s = IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Proto=>'tcp',Timeout=>5)
        or die " connect fail: $!";
    print $s "GET $path HTTP/1.0\r\nHost: $host\r\n\r\n";
    while (<$s>) { print }
    close $s;
}

sub cmd_ping_tcp {
    my ($host,$port,$to) = @_;
    $host or die_usage();
    $port ||= 80; $to ||= 2;
    print "[",ts,"] TCP reachability (ping-tcp) $host:$port (timeout ${to}s)\n";
    my $s = IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Proto=>'tcp',Timeout=>$to);
    print $s ? "  reachable\n" : "  unreachable\n";
    close $s if $s;
}

sub cmd_traceroute_tcp {
    my ($dst,$port,$max,$to) = @_;
    $dst or die_usage();
    $port ||= 80; $max ||= 20; $to ||= 2;
    print "[",ts,"] traceroute-tcp to $dst:$port  (hops=$max timeout=${to}s)\n";
    # Best effort; may be blocked by policy/runtime.
    my $addr = inet_aton($dst) or die "Cannot resolve $dst\n";
    for my $ttl (1..$max) {
        socket(my $s, PF_INET, SOCK_STREAM, getprotobyname("tcp")) or die "socket: $!";
        # IP_TTL is 2 on many systems; on some minimal images this might fail.
        my $IP_TTL = 2; # SOL_IP is usually 0, IP_TTL often 2; hardcode to avoid non-portable constants
        eval {
            # Fallback to Socket constants if available
            require Socket;
            $IP_TTL = Socket::IP_TTL() if defined &Socket::IP_TTL;
        };
        eval { setsockopt($s, Socket::SOL_IP(), $IP_TTL, pack("I",$ttl)) } or do {
            print sprintf("%2d  %s\n",$ttl,"* (setsockopt denied)");
            close $s; next;
        };
        my $hit;
        eval {
            local $SIG{ALRM}=sub{ die "timeout\n" }; alarm $to;
            connect($s, sockaddr_in($port, $addr)) and $hit=1;
            alarm 0;
        };
        if ($hit) { print sprintf("%2d  %s\n",$ttl,"reached"); close $s; last }
        else      { print sprintf("%2d  %s\n",$ttl,"*"); close $s }
    }
}

sub cmd_whoami {
    print "[",ts,"] Who am I / env\n";
    my $uid = $<; my $gid = $(;
    chomp(my $user = `id -un 2>/dev/null` || "");
    chomp(my $groups = `id -Gn 2>/dev/null` || "");
    print "  user: $user  uid=$uid  gid=$gid\n" if $user ne "";
    print "  groups: $groups\n" if $groups ne "";
    print "  hostname: ", (`hostname 2>/dev/null`||'')[0] || "(unknown)";
    print "  shell: $ENV{SHELL}\n" if $ENV{SHELL};
    print "  PATH: $ENV{PATH}\n" if $ENV{PATH};
}

# ---------------------------------------
# Main
# ---------------------------------------
my $cmd = shift || '';
$cmd or die_usage();

if    ($cmd eq 'ifaces')          { cmd_ifaces() }
elsif ($cmd eq 'routes')          { cmd_routes() }
elsif ($cmd eq 'arp')             { cmd_arp() }
elsif ($cmd eq 'sockets')         { cmd_sockets(shift||'tcp') }
elsif ($cmd eq 'resolv')          { cmd_resolv() }
elsif ($cmd eq 'dns')             { cmd_dns(shift) }
elsif ($cmd eq 'tcp')             { cmd_tcp(@ARGV) }
elsif ($cmd eq 'http-head')       { cmd_http_head(@ARGV) }
elsif ($cmd eq 'http-get')        { cmd_http_get(@ARGV) }
elsif ($cmd eq 'ping-tcp')        { cmd_ping_tcp(@ARGV) }
elsif ($cmd eq 'traceroute-tcp')  { cmd_traceroute_tcp(@ARGV) }
elsif ($cmd eq 'whoami')          { cmd_whoami() }
else { die_usage() }
