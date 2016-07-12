#!/usr/bin/perl -w

# Getopt::Std module from the perl package
use Getopt::Std;

my %Options;
getopt('s', \%Options);

if (defined($Options{'s'})) {
    $saddr = $Options{'s'};
} else {
    print "saddr not given\n";
    exit(-1);
}

sub hex2dec($) { 
		return hex $_[0] }

sub parse_saddr
{
    my $saddr = $_[0];

    ($f1, $f2, $p1, $p2, @addr) = unpack("A2A2A2A2A2A2A2A2", $saddr);
    $family = hex2dec($f1) + 256 * hex2dec($f2);
    $port = 256 * hex2dec($p1) + hex2dec($p2);
    $ip1 = hex2dec($addr[0]);
    $ip2 = hex2dec($addr[1]);
    $ip3 = hex2dec($addr[2]);
    $ip4 = hex2dec($addr[3]);
    #print "$saddr\n";
				print "$family ";

    if ($family eq 2) { #&& $ip1 ne 0) {
        my $dst_addr = "$ip1.$ip2.$ip3.$ip4:$port";
        print "$dst_addr\n";
    } elsif ($family eq 1) {
        $tmp1 = 0;
        ($tmp1, $tmp2) = unpack("A4A*", $saddr);
        my $file = pack("H*", $tmp2);
								$file =~ s/\0//g;
        print "file:$file\n";
								#print "/tmp/.X11-unix/X0\n";
    } else {
        print "$saddr\n";
    }
}

&parse_saddr($saddr);
