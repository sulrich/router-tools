#!/opt/local/bin/perl
#
# -*- Mode: perl; tab-width: 2 -*- *
# parse a configuration file - determine the hostname from the configuration
# sniff the relevant interfaces and grab relevant IP address information.
#
# from this information we should be able to build a graph that has the
# necessary elements to build a graphviz top file that allows us to generate
# pretty pictures.
# 

use strict;  # just to be difficult

use Net::Netmask;
use GraphViz; 
use Getopt::Long;

my $debug = 0;

my %netblocks = {}; # HoA - $networks{base_netblock}[xxx] = base members 
my %addrinfo  = {}; # HoH - #addrinfo{"ipaddr/mask"}{key} = value
my %edgecount = (); 
my %opts      = ();

my @nodes = ();
my %edges = ();

GetOptions(
		'dot-out=s'  => \$opts{dot_out},
		'png-out=s'  => \$opts{png_out},
		'help'       => \$opts{help},
		);


if ( defined($opts{help}) ) {
	print <<EOF;

mktopo.pl

 --dot-out=<path_to_dot_output_file> 

   if you're goign to feed this into GraphViz macros yourself, use this.

 --png-out=<path_to_png_output_file>

   if you're looking for instant gratification, use this.  note, it's
   probably going to look like crap, but depending on the complexity you
   might get something useful here.

EOF
exit(0);

}

while (@ARGV) {
	my $config = shift @ARGV;
	&parseConfig($config);
}

# the GraphViz shiz
my $g = GraphViz->new(layout => 'neato', overlap => 'false');

foreach my $node (@nodes) {
		$g->add_node($node,
								 # shape    => 'circle',
								 label    => $node,
								 fontsize => 8,
								);
}

foreach my $j ( sort keys %netblocks ) {
	if ( $#{$netblocks{$j}} > 0 && $#{$netblocks{$j}} <= 1 ) {
		if ($addrinfo{$netblocks{$j}[0]}{'host'} eq $addrinfo{$netblocks{$j}[1]}{'host'}) {
			print STDERR "HAIRPIN - $j\n" .
			"  $addrinfo{$netblocks{$j}[0]}{'host'} - " .
  		"$addrinfo{$netblocks{$j}[0]}{'intf'} ($addrinfo{$netblocks{$j}[0]}{'ipaddr'})\n" .
			"  $addrinfo{$netblocks{$j}[1]}{'host'} - " .
			"$addrinfo{$netblocks{$j}[1]}{'intf'} ($addrinfo{$netblocks{$j}[1]}{'ipaddr'})\n";
			next;
		}
		
		my $edge_cpl_fwd = 
				$addrinfo{$netblocks{$j}[0]}{'host'}."-".$addrinfo{$netblocks{$j}[1]}{'host'};
		my $edge_cpl_rev = 
				$addrinfo{$netblocks{$j}[1]}{'host'}."-".$addrinfo{$netblocks{$j}[0]}{'host'};
		
		$edgecount{$edge_cpl_fwd}++;
		$edgecount{$edge_cpl_rev}++;
		
		if ($edgecount{$edge_cpl_fwd} > 1 || $edgecount{$edge_cpl_rev} > 1) {
			$edges{$edge_cpl_fwd}{'label'} .= ".";
			next;
		} else {
			$edges{$edge_cpl_fwd}{'from_node'} = $addrinfo{$netblocks{$j}[0]}{'host'},
			$edges{$edge_cpl_fwd}{'from_intf'} = $addrinfo{$netblocks{$j}[0]}{'intf'},
			$edges{$edge_cpl_fwd}{'to_node'}   = $addrinfo{$netblocks{$j}[1]}{'host'},
			$edges{$edge_cpl_fwd}{'to_intf'}   = $addrinfo{$netblocks{$j}[1]}{'intf'},
			$edges{$edge_cpl_fwd}{'label'}     = $j;
		}
		
	}	elsif ( $#{$netblocks{$j}} > 1 ) {
		# multipoint edge
		my (%mp_from_nodes, %mp_to_nodes) = "";
		
		for my $k ( 0 .. $#{ $netblocks{$j} } ) {
			my $mp_node = $addrinfo{$netblocks{$j}[$k]}{'host'};
			next if defined($mp_from_nodes{$mp_node});  # node exists
			next if defined($mp_to_nodes{$mp_node});
			
			$mp_from_nodes{$mp_node} = $addrinfo{$netblocks{$j}[$k]}{'intf'};
			$mp_to_nodes{$mp_node}   = $addrinfo{$netblocks{$j}[$k]}{'intf'};
		}
		
		foreach my $from_node (sort keys %mp_from_nodes) {
			foreach my $to_node (sort keys %mp_to_nodes) {
				next if $to_node eq $from_node; # skip ourself

				my $edge_cpl_fwd = $from_node . "-" . $to_node;
			  my $edge_cpl_rev = $to_node   . "-" . $from_node;
				
				next if (exists($edges{$edge_cpl_fwd}) || exists($edges{$edge_cpl_rev}));
				# skip duplicates

				$edges{$edge_cpl_fwd}{'from_node'} = $from_node;
				$edges{$edge_cpl_fwd}{'from_intf'} = $mp_from_nodes{$from_node};
				$edges{$edge_cpl_fwd}{'to_node'}   = $to_node;
				$edges{$edge_cpl_fwd}{'to_intf'}   = $mp_to_nodes{$to_node};
				$edges{$edge_cpl_fwd}{'label'}     = $j;
			}
		}
	}
}


foreach my $e ( sort keys(%edges) ) {
	$g->add_edge($edges{$e}{'from_node'} => $edges{$e}{'to_node'},
										 label => $edges{$e}{'label'},
										 headlabel => $edges{$e}{'from_intf'},
										 taillabel => $edges{$e}{'to_intf'},
										 arrowhead => 'none',
										 arrowtail => 'none',
										 fontsize  => 8,
										);
}


if (defined $opts{dot_out}) { $g->as_text( $opts{dot_out} ); }
if (defined $opts{png_out}) { $g->as_text( $opts{png_out} ); }

if (!defined($opts{dot_out}) || !defined($opts{png_out})) {
	my $foo = $g->as_text( $opts{dot_out} );
	print $foo;
}


#---------------------------------------------------------------------

sub parseConfig() {
	my ($config_file) = @_;
	my ($hostname, $capture_mode, , $current_int) = "";
	my @intbuf = ();

	print "-- beg - parsing config: $config_file\n" if $debug >= 2;
	open (CONFIG_FILE, $config_file) || die "error opening: $config_file\n";
	
	# configuration specific information 
	while (<CONFIG_FILE>) {
		if (/^hostname (.*)$/i) { 
			$hostname = $1; 
			print "-- hostname: $hostname\n" if $debug >= 2;
			push @nodes, $hostname; # add to the array of nodes
		}
		
		if (/^interface (.*)$/i && $capture_mode == 0) {
			next if $1 =~ /loopback/i;
			
			$capture_mode = 1;     # start capturing for the interface buffer
			$current_int = $1;
			next;                  # go to the next line (only append 1x)
		} elsif ($capture_mode == 1 && !(/^\!/)) {
			push(@intbuf, $_);
		} elsif ($capture_mode == 1 && (/^\!/)) {
			# end of interface stanza
			$capture_mode = 0;
			print "  -- parsing int:  $hostname - $current_int\n" if $debug >= 2;
			&parseInterface($hostname, $current_int, @intbuf);
			@intbuf = (); # reset $intbuf
		}
	}
	close(CONFIG_FILE);
	print "-- end - parsing config: $config_file\n" if $debug >= 2;
}



#---------------------------------------------------------------------

sub parseInterface() {
	my ($hostname, $int, @int_info) = @_;

	my ($ipaddr, $netmask, $vlan_list, $switchport) = ""; # init int specific vars

	foreach my $i (@int_info) {
		# grab ip address info
		# if ($i =~ /secondary/i) { print "$i"; }
		next if ($i =~ /secondary/i); # do we need to do this?
		if ($i =~ /^\s+shutdown/i) {
				print "    - skip down int: $hostname - $int (int shutdown)\n" if $debug >= 2;
				return 0;
		}

		if ($i =~ /switchport mode trunk/ ) { $switchport = 1; }
		if ($i =~ /^\s+switchport trunk allowed vlan (.*)/) {
			$vlan_list = $1;
			$switchport = 1;
		}


		if ($i =~ /^\s+ip address (.*) (.*)/i) {
				$ipaddr = $1; $netmask = $2;
		} elsif ($i =~ /no ip address$/i && $switchport != 1) {
				print "    - skipping: $hostname - $int (no ip address)\n" if $debug >= 2;
				return 0;
		}
	}

				

	# should probable develop some form of L2 topology derivation from
	# switches - possible to get sh cdp neigh? or equivalent output?
	return if ($ipaddr eq "" || $netmask eq "");


	my $block = new2 Net::Netmask($ipaddr, $netmask);
	my $bits = $block->bits();
	my $base = $block->base();

	push @{ $netblocks{"$base\/$bits"} }, "$ipaddr\/$bits";

	$addrinfo{"$ipaddr\/$bits"}{"host"}   = $hostname;
	$addrinfo{"$ipaddr\/$bits"}{"intf"}   = $int;
	$addrinfo{"$ipaddr\/$bits"}{"ipaddr"} = "$ipaddr\/$bits";
	print "    - ip addr: $hostname - $int ($ipaddr\/$bits)\n" if $debug >= 2;

}
