package Net::DNS::Paranoid;
use strict;
use warnings;
use 5.008008;
our $VERSION = '0.11';

use Class::Accessor::Lite (
    rw => [qw(timeout blocked_hosts whitelisted_hosts resolver)]
);
use Net::DNS;
use IPv6::Address;

sub new {
    my $class = shift;
    my %args = @_ ==1 ? %{$_[0]} : @_;
    $args{resolver} ||= Net::DNS::Resolver->new;
    $args{whitelisted_hosts} ||= [];
    $args{blocked_hosts} ||= [];
    bless {
        timeout => 15,
        %args
    }, $class;
}

sub resolve {
    my ($self, $name, $start_time, $timeout) = @_;
    $start_time = time() if not defined $start_time;
    $timeout = $self->timeout if not defined $timeout;

    my ($addrs, $errmsg) = $self->_resolve($name, $start_time, $timeout);
    return ($addrs, $errmsg);
}

sub _resolve {
    my ($self, $host, $start_time, $timeout, $depth) = @_;
    my $res = $self->resolver;
    $depth ||= 0;

    return (undef, "CNAME recursion depth limit exceeded.") if $depth > 10;
    return (undef, "DNS lookup resulted in bad host.") if $self->_bad_host($host);

    # return the IP address if it looks like one and wasn't marked bad
    return ([$host]) if $host =~ /^\d+\.\d+\.\d+\.\d+$/;

    # We ask sequentially for IPv4 and IPv6 name resolution. This can later
    # be done in parallel here
    my @responses;
    for my $type ('A', 'AAAA') {
        my $sock = $res->bgsend($host, $type)
            or return (undef, "No sock from bgsend");

        # wait for the socket to become readable, unless this is from our test
        # mock resolver.
        unless ($sock && $sock eq "MOCK") {
            my $rin = '';
            vec($rin, fileno($sock), 1) = 1;
            my $nf = select($rin, undef, undef, $self->_time_remain($start_time));
            return (undef, "DNS lookup timeout") unless $nf;
        }

        my $packet = $res->bgread($sock)
            or return (undef, "DNS bgread failure");
        $sock = undef;
        push @responses, $packet;
    }
    # Find the first reply that has some answers
    (my $packet) = grep { 0+$_->answer } @responses;
    $packet //= shift @responses; # otherwise, take any reply with no answer

    my @addr;
    my $cname;
    foreach my $rr ($packet->answer) {
        if ($rr->type eq "A") {
            return (undef, "Suspicious DNS results from A record") if $self->_bad_host($rr->address);
            # untaints the address:
            push @addr, join(".", ($rr->address =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/));
        } elsif ($rr->type eq "CNAME") {
            # will be checked for validity in the recursion path
            $cname = $rr->cname;
        } elsif($rr->type eq "AAAA") {
            my $addr = eval { IPv6::Address->new( $rr->address . "/128" )};
            return (undef, "Suspicious DNS results from AAAA record") if !$addr;
            return (undef, "Suspicious DNS results from AAAA record") if $self->_bad_host($addr->addr_string);
            push @addr, $addr->addr_string;
        }
    }

    return (\@addr) if @addr;
    return ([]) unless $cname;
    return $self->_resolve($cname, $start_time, $timeout, $depth + 1);
}

# returns seconds remaining given a request
sub _time_remain {
    my $self       = shift;
    my $start_time = shift;

    return $start_time + $self->{timeout} - time();
}

sub _host_list_match {
    my $self = shift;
    my $list_name = shift;
    my $host = shift;

    foreach my $rule (@{ $self->{$list_name} || [] }) {
        if (ref $rule eq "CODE") {
            return 1 if $rule->($host);
        } elsif (ref $rule) {
            # assume regexp
            return 1 if $host =~ /$rule/;
        } else {
            return 1 if $host eq $rule;
        }
    }
}


sub _bad_host {
    my $self = shift;
    my $host = lc(shift);

    return 0 if $self->_host_list_match("whitelisted_hosts", $host);
    return 1 if $self->_host_list_match("blocked_hosts", $host);
    return 1 if
        $host =~ /^localhost$/i ||    # localhost is bad.  even though it'd be stopped in
                                      #    a later call to _bad_host with the IP address
        $host =~ /\s/i;               # any whitespace is questionable

    if( $host =~ /:/ ) {
        # It's an IPv6 address
        return $self->_bad_ipv6_address( $host );
    }

    # Let's assume it's an IP address now, and get it into 32 bits.
    # If at any time something doesn't look like a number, then it's
    # probably a hostname and we've already either whitelisted or
    # blacklisted those, so we'll just say it's okay and it'll come
    # back here later when the resolver finds an IP address.
    my @parts = split(/\./, $host);
    return 0 if @parts > 4;

    # un-octal/un-hex the parts, or return if there's a non-numeric part
    my $overflow_flag = 0;
    foreach (@parts) {
        return 0 unless /^\d+$/ || /^0x[a-f\d]+$/;
        local $SIG{__WARN__} = sub { $overflow_flag = 1; };
        $_ = oct($_) if /^0/;
    }

    # a purely numeric address shouldn't overflow.
    return 1 if $overflow_flag;

    my $addr;  # network order packed IP address

    if (@parts == 1) {
        # a - 32 bits
        return 1 if
            $parts[0] > 0xffffffff;
        $addr = pack("N", $parts[0]);
    } elsif (@parts == 2) {
        # a.b - 8.24 bits
        return 1 if
            $parts[0] > 0xff ||
            $parts[1] > 0xffffff;
        $addr = pack("N", $parts[0] << 24 | $parts[1]);
    } elsif (@parts == 3) {
        # a.b.c - 8.8.16 bits
        return 1 if
            $parts[0] > 0xff ||
            $parts[1] > 0xff ||
            $parts[2] > 0xffff;
        $addr = pack("N", $parts[0] << 24 | $parts[1] << 16 | $parts[2]);
    } elsif (@parts == 4) {
        # a.b.c.d - 8.8.8.8 bits
        return 1 if
            $parts[0] > 0xff ||
            $parts[1] > 0xff ||
            $parts[2] > 0xff ||
            $parts[3] > 0xff;
        $addr = pack("N", $parts[0] << 24 | $parts[1] << 16 | $parts[2] << 8 | $parts[3]);
    } else {
        return 1;
    }

    my $haddr = unpack("N", $addr); # host order IP address
    return 1 if
        ($haddr & 0xFF000000) == 0x00000000 || # 0.0.0.0/8
        ($haddr & 0xFF000000) == 0x0A000000 || # 10.0.0.0/8
        ($haddr & 0xFF000000) == 0x7F000000 || # 127.0.0.0/8
        ($haddr & 0xFFF00000) == 0xAC100000 || # 172.16.0.0/12
        ($haddr & 0xFFFF0000) == 0xA9FE0000 || # 169.254.0.0/16
        ($haddr & 0xFFFF0000) == 0xC0A80000 || # 192.168.0.0/16
        ($haddr & 0xFFFFFF00) == 0xC0000200 || # 192.0.2.0/24  "TEST-NET" docs/example code
        ($haddr & 0xFFFFFF00) == 0xC0586300 || # 192.88.99.0/24 6to4 relay anycast addresses
         $haddr               == 0xFFFFFFFF || # 255.255.255.255
        ($haddr & 0xF0000000) == 0xE0000000;  # multicast addresses

    # as final IP address check, pass in the canonical a.b.c.d decimal form
    # to the blacklisted host check to see if matches as bad there.
    my $can_ip = join(".", map { ord } split //, $addr);
    return 1 if $self->_host_list_match("blocked_hosts", $can_ip);

    # looks like an okay IP address
    return 0;
}

# From https://en.wikipedia.org/wiki/IPv6_address
our %blocked_ipv6_ranges = (
    examples_2001 => IPv6::Address->new('2001:db8::/32'),
    examples_3fff => IPv6::Address->new('3fff::/20'),
    private       => IPv6::Address->new('fc00::/7'),
    link_local    => IPv6::Address->new('fe80::/64'),
);

sub _bad_ipv6_address {
    my $self = shift;
    my $host = lc(shift);

    return 1 if $host eq '::'; # Unspecified address

    return 0 if $self->_host_list_match("whitelisted_hosts", $host);
    return 1 if $self->_host_list_match("blocked_hosts", $host);
    return 1 if $host =~ m![^a-f0-9:]!;

    my $addr = IPv6::Address->new("$host/128");
    return 1 if ! $addr; # malformed IPv6 address
    return 0 if $self->_host_list_match("whitelisted_hosts", $addr);
    return 1 if $self->_host_list_match("blocked_hosts", $addr);

    return 1 if $addr->is_loopback;
    return 1 if $addr->is_multicast;

    for my $range (values %blocked_ipv6_ranges) {
        return 1 if $range->contains($addr);
    }

    # as final IP address check, pass in the canonical a.b.c.d decimal form
    # to the blacklisted host check to see if matches as bad there.
    return 1 if $self->_host_list_match("blocked_hosts", $addr->addr_string( nocompress => 1 ));

    # looks like an okay IP address
    return 0;
}

1;
__END__

=head1 NAME

Net::DNS::Paranoid - paranoid dns resolver

=head1 SYNOPSIS

    my $dns = Net::DNS::Paranoid->new();
    $dns->blocked_hosts([
        'mixi.jp',
        qr{\.dev\.example\.com$},
    ]);
    $dns->whitelisted_hosts([
        'twitter.com',
    ]);
    my ($addrs, $errmsg) = $dns->resolve('mixi.jp');
    if ($addrs) {
        print @$addrs, $/;
    } else {
        die $errmsg;
    }

=head1 DESCRIPTION

This is a wrapper module for Net::DNS.

This module detects IP address / host names for internal servers.

=head1 METHODS

=over 4

=item my $dns = Net::DNS::Paranoid->new(%args)

Create new instance with following parameters:

=over 4

=item timeout

DNS lookup timeout in secs.

Default: 15 sec.

=item blocked_hosts: ArrayRef[Str|RegExp|Code]

List of blocked hosts in string, regexp or coderef.

=item whitelisted_hosts: ArrayRef[Str|RegExp|Code]

List of white listed hosts in string, regexp or coderef.

=item resolver: Net::DNS::Resolver

DNS resolver object, have same interface as Net::DNS::Resolver.

=back

=item my ($addrs, $err) = $dns->resolve($name[, $start_time[, $timeout]])

Resolve a host name using DNS. If it's bad host, then returns $addrs as undef, and $err is the reason in string.

$start_time is a time to start your operation. Timeout value was counted from it.
Default value is time().

$timeout is a timeout value. Default value is C<$dns->timeout>.

=back

=head1 USE WITH Furl

You can use L<Net::DNS::Paranoid> with Furl!

    use Furl::HTTP;
    use Net::DNS::Paranoid;

    my $resolver = Net::DNS::Paranoid->new();
    my $furl = Furl->new(
        inet_aton => sub {
            my ($host, $errmsg) = $resolver->resolve($_[0], time(), $_[1]);
            die $errmsg unless $host;
            Socket::inet_aton($host->[0]);
        }
    );

=head1 USE WITH LWP

I shipped L<LWPx::ParanoidHandler> to wrap this module.
Please use it.

=head1 THANKS TO

Most of code was taken from L<LWPx::ParanoidAgent>.

=head1 AUTHOR

Tokuhiro Matsuno < tokuhirom @A gmail DOT. com>

=head1 LICENSE

Copyright (C) Tokuhiro Matsuno

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
