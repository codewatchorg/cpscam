#!/usr/bin/perl

use strict 'refs';
use strict 'subs';
use strict 'vars';

my (
    $pcap_err,          $pcap_descr,
    $pcap_timeout,      $pcap_promisc,
    $pcap_snaplen,      $pcap_int,
    $starttime,         $nowtime,
    $arg_ip,            $arg_mask,
    $l2offset,          $maxinactive,
    $lmask,             $llocalip,
    $lobsrvdip,         $progname,
    $logoffurl,         $listentime,
    $elapsed,           $host,
    $ip_obj,            $eth_obj,
    %packetcounth,      %inactivityh,
);


sub checkmodules; checkmodules;
use Socket;
use Net::Pcap;
use NetPacket::IP;
use NetPacket::Ethernet qw(:strip);

#$SIG{INT} = \&sigint_handler;

$arg_ip = $ARGV[1];
$arg_mask = $ARGV[2];

if ($ARGV[4]) {
    $logoffurl = $ARGV[4];
} else {
    $logoffurl = "logoff.hotspot.t-mobile.com";
}

# Constants
$pcap_int = $ARGV[0];
$pcap_timeout = 1000; # in ms
$pcap_promisc = 1;
$pcap_snaplen = 1500;
$l2offset = 14;
$maxinactive = 120;
$progname = $0;
$progname =~ s,.*/,,;    # only basename left in progname

# Set the duration between reporting host status
if ($ARGV[3]) {
    $listentime = $ARGV[3];
} else {
    $listentime = 15;
}

# main

if (@ARGV < 3) {
    usage('');
}

if ($arg_mask =~ '\.') {
    # Mask was passed as dotted-quad
    $lmask = dottedquad2long($arg_mask);
} else {
    # assume mask is passwd as bit length integer
    $lmask = makemask($arg_mask);
}
$llocalip = dottedquad2long($arg_ip);

# Open capture interface and start looping on each packet captured
print "Capturing traffic .. \n";
if ($pcap_descr = Net::Pcap::open_live
        ($pcap_int,$pcap_snaplen,$pcap_promisc,$pcap_timeout,\$pcap_err)) {

    $starttime = time();
    # Loop indefinitely, BPF filter for only IP packets
    Net::Pcap::loop($pcap_descr, -1, \&process_pkt, 'ip');

} else {

    print "Could not open device \'$pcap_int\' for capture: $pcap_err\n";
    exit(1);

}




# --- begin subroutines ---
sub process_pkt {

    my ($user, $hdr, $pkt) = @_;

    $ip_obj = NetPacket::IP->decode(eth_strip($pkt));
    $eth_obj = NetPacket::Ethernet->decode($pkt);

    $lobsrvdip = dottedquad2long($ip_obj->{src_ip});

    # We only want local address, return if a remote source
    return unless (netcomp($llocalip, $lmask, $lobsrvdip));

    # Increment packet count hash for this address, reset inactivity value
    $packetcounth{$ip_obj->{src_ip}}++;
    $inactivityh{$ip_obj->{src_ip}} = 0;

    if ($ip_obj->{data} =~ /$logoffurl/) {
        # This source has logged off, so remove it from the hashes
        delete($packetcounth{$ip_obj->{src_ip}});
        delete($inactivityh{$ip_obj->{src_ip}});
        print "Host at $ip_obj->{src_ip} logged out.\n";
        return 0;
    }

    $elapsed = time() - $starttime;

    if ($elapsed > $listentime) {

        foreach $host (keys (%packetcounth)) {
            if ($packetcounth{$host} == 0) {
                $inactivityh{$host} += $elapsed;
                if ($inactivityh{$host} > $maxinactive) {
                    print "The host at " . $host . "\/" . 
                    printmac($eth_obj->{src_mac}) .
                    " has been inactive for $maxinactive seconds...\n";
                    Net::Pcap::close($pcap_descr);
                    exit 0;
                }
            }

            # Reset this parameter to 0 to give hosts another change at
            # inactivity
            $packetcounth{$host} = 0;
        }

        $starttime += $elapsed;
        &printinactivity;
    }

}

sub printmac {
    # hack, hack, hack
    my ($uglymac) = @_;
    my $prettymac = substr($uglymac, 0, 2) . ":" . substr($uglymac, 2, 2) .
              ":" . substr($uglymac, 4, 2) . ":" . substr($uglymac, 6, 2) .
              ":" . substr($uglymac, 8, 2) . ":" . substr($uglymac, 10, 2);
    return $prettymac;
}

sub printinactivity {
    print localtime() . "\n";
    foreach my $host (keys (%inactivityh)) {
        if ($inactivityh{$host} > 0) {
            print "Host $host has been inactive for " . $inactivityh{$host} . 
                  " seconds.\n";
        }
    }
}

sub sigint_handler {
    # Close pcap gracefully after CTRL/C
    if ($pcap_descr) {

        print "\n";
    }
    print "Caught CTRL/C, exiting.\n";
    exit(0);
}

sub checkmodules {

    eval {
        require Socket;
    };
    if ($@) {
        print <<EOT;

This tool requires the Socket Perl module.  This module is typically bundled
with Perl distributions, something may be amiss with your Perl installation.

Quitting.

EOT
        exit(-1);
    }

    eval {
        require Net::Pcap;
    };
    if ($@) {
        print <<EOT;

The Net::Pcap module is required for this tool.  Download this tool from the
CPAN website (search.cpan.org), or install via
"perl -MCPAN -e 'install Net::Pcap'".  You will need libpcap for this module.

Windows users using ActiveState Perl can install this module with the ppm tool.
As of 2/26/2004 this module isn't in the standard PPM repository, but you can
install it from JL Morel's website with
"ppm install http://www.bribes.org/perl/ppm/Net-Pcap.ppd".  You must also
install the WinPcap software from http://winpcap.polito.it/.

Quitting.

EOT
        exit(-1);
    }

    eval {
        require NetPacket::IP;
    };
    if ($@) {
        print <<EOT;

The NetPacket::IP module is required for this tool.  Download this tool from
the CPAN website (search.cpan.org), or install via
"perl -MCPAN -e 'install NetPacket::IP'".  You will need libpcap for this
module.

Windows users using ActiveState Perl can install this module with the ppm tool:
"ppm install NetPacket-IP".  You must also
install the WinPcap software from http://winpcap.polito.it/.

Quitting.

EOT
        exit(-1);
    }
}


sub usage {
    my($msg) = @_;
    select(STDERR);
    print STDERR "$progname: $msg\n" unless ($msg eq "");
    print "Usage: $progname ethX localip mask [timerduration] [logoff url]\n";
    print "\n";
    print "You will need to edit this tool to specify the logoff URL (at least partial path\nor hostname) to identify logged-out clients (\$logoffurl).\n";
    exit(1);
}


# Accepts local address, netmask and second address as long integers
# Returns true when two addresses are on the same local network
sub netcomp {

    my ($firstip, $mask, $secondip) = @_;
    my $netnum = $firstip & $mask;
    if (($secondip & $mask) == $netnum) {
        return 1;
    } else {
        return 0;
    }
}

# converts decimal dotted quad string to network ordered long
sub dottedquad2long {

    return unpack('N', inet_aton(shift));

}

# converts network ordered long to dotted quad string
sub long2dottedquad {

    return inet_ntoa(pack('N', shift));

}

# returns netmask as network ordered long
sub makemask {

    my $mask_length = shift;
    my $binary = '1' x $mask_length . '0' x (32 - $mask_length);
    return bin2long($binary);

}

# converts 32bit binary to network ordered long
sub bin2long {

    return unpack('N', pack('B32', shift));

}

# --- end subroutines ---

