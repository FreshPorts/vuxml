# Copyright (c) 2004 Matthew Seaman. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#    1.  Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#    2.  Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

#
# @(#) $Id: vuxml_parsing.pm,v 1.6 2013-01-16 15:37:57 dan Exp $
#
# Parse the Vulnerabilities and Exposures (vuxml) database extracting
# the entries for loading into a RDBMS.
#
# Permit filtering of the entries by System Name (eg FreeBSD) and
# version
#
# DTDs etc for vuxml obtained from the security/vuxml port, and are
# installed in ${LOCALBASE}/share/xml/dtd/vuxml/ by default.
#
# The vulnerabilty database itself is just a file within the port
# directory:
#
#     /usr/ports/security/vuxml/vuln.xml

package FreshPorts::vuxml_parsing_via_dom;

require FreshPorts::committer_opt_in;

use strict;
use Carp;
use XML::Parser;
use DBI;

use Digest::SHA qw(sha256_hex);

use base qw( Class::Observable );

# Class variables

our ($VuXML);

# Call like this:
#
# $v = new FreshPorts::vuxml_parsing(DBHandle      => $dbh,
#                                    Stream        => IO::File,
#                                    UpdateInPlace => $UpdateInPlace
#                                    Node          => $Node);
# where Node is based on XML::DOM::Parser->findnodes()
#
# DBHandle is a database handle from the DBI module. Required (well,
# if you want to write to a database it's necessary)
#
# Stream is optional, and defaults to reading STDIN.  Pass either an
# IO::Handle or a glob: *GLOB or a glob ref: \*GLOB
#
# UpdateInPlace is optional, defaults to TRUE.  Indicates whether or not
# the code should attempt to update existing VuXML entries.
#

sub new
{
    my $caller = shift;
    my $class  = ref($caller) || $caller;
    my %args   = ref( $_[0] ) eq 'HASH' ? %{ shift() } : @_;
    my $self;

    # There can be only one! Since we keep $self hanging around as a
    # Class variable, more than one instance would be a disaster.
    # Therefore, all calls to new() (except the first or when
    # DESTROY() has been called) just return a reference to the same
    # object.

    if ( $VuXML && $VuXML->isa(__PACKAGE__) ) {
        $self = $VuXML;
        return bless $self, $class;
    }

    $VuXML = $self = {};
    bless $self, $class;

    # Initialise various instance variables

    $self->{_known_ref_types} = qr/
		^( url       |
		   mlist     |
		   cvename   |
		   bid       |
		   certsa    |
		   certvu    |
		   uscertsa  |
		   uscertta  |
		   freebsdsa |
		   freebsdpr )$
		   /x;

    # Dispatch table for call-back functions triggered on starting
    # <element> tags

    $self->{start_handlers} = {};
    for my $tag (qw(vuln cancelled package system range)) {
        no strict qw(refs);
        my $handle_start_tag = "handle_start_$tag";

        $self->{start_handlers}{$tag} = \&$handle_start_tag;
    }

    # Dispatch table for call-back functions triggered on closing
    # </element> tags

    $self->{end_handlers} = {};
    for my $tag (
        qw( topic name architecture category range lt gt le ge eq
        description url mlist cvename bid certsa certvu uscertsa
        uscertta freebsdsa freebsdpr discovery entry modified )
      )
    {
        no strict qw(refs);
        my $handle_end_tag = "handle_end_$tag";

        $self->{end_handlers}{$tag} = \&$handle_end_tag;
    }

    # Remember context when saving <package> or <system> data
    $self->{_target} = undef;
    
    #  argument should be 0 or 1
    if ( !defined $args{Node} ) {
        croak "new(): Argument is not a Node: Node => $args{Node}"
          unless ( $args{Node}->isa("XML::DOM::Node") );

        $self->{node} = $args{Node};
    }


    # now what, do I do here? I have the node above
    # but why instantiate XML::Parser if XML::DOM::Parser
    # has the same functionality?

    unless ( $self->{xml_parser}
        && $self->{xml_parser}->isa('XML::Parser') )
    {
        $self->{xml_parser} = new XML::Parser(
            Pkg      => __PACKAGE__,
            Handlers => {
                Start => \&handle_start,
                End   => \&handle_end,
                Char  => \&handle_char,
            }
        );
    }

    # Marshalling operator+version values from the <range> element
    $self->{_range_buffer} = [ undef, undef, undef, undef ];

    # Argument handling.

    if ( defined $args{Stream} ) {

        # There are too many things that can be used as filehandles...

        croak "new(): Argument is not a filehandle: Stream => $args{Stream}"
          unless ( ref \$args{Stream} eq 'GLOB'
            || ref $args{Stream} eq 'GLOB'
            || $args{Stream}->isa("IO::Handle") );
        $self->{input} = $args{Stream};
    } else {
        $self->{input} = *STDIN;
    }

    # DBHandle argument should be a database handle

    if ( defined $args{DBHandle} ) {
        croak "new(): Argument is not a DB handle: DBHandle => $args{DBHandle}"
          unless ( $args{DBHandle}->isa("DBI::db") );
        $self->{db_handle} = $args{DBHandle};
    }

    # UpdateInPlace argument should be 0 or 1
    if ( defined $args{UpdateInPlace} ) {
        $self->{update_in_place} = $args{UpdateInPlace};
    }

    # Initialise parsed data area

    $self->_initialise(@_);

    return $self;
}

sub database_updated
{
    my __PACKAGE__ $self = shift;
    print "checking database_updated\n";

    return $self->{database_updated};
}

# Print out parsed data -- mostly for debugging purposes
sub print_self
{
    my __PACKAGE__ $self = shift;

    print "vid:           ", $self->vid(), "\n";
    if ( defined $self->cancelled() ) {
        print "cancelled";
        if ($self->cancelled())
        {
            print " -- superseded by: '", $self->cancelled(), "'";
        }
        print "\n";
    } else {
        print "topic:         ", $self->topic(), "\n";

        if ( $self->packages() ) {
            print "packages:\n";
            for my $package ( $self->packages() ) {
                $package->print_self();
            }
        }

        if ( $self->systems() ) {
            print "systems:\n";
            for my $system ( $self->systems() ) {
                $system->print_self();
            }
        }

        print "description:", $self->description(), "\n";

        print "references:\n";
        foreach my $i ( $self->references() ) {
            print "    ", $i->[0], ":", " " x ( 10 - length( $i->[0] ) ),
              $i->[1], "\n";
        }

        print "dates:\n";
        print "    discovery: ", $self->date_discovery(), "\n";
        print "    entry:     ", $self->date_entry(),     "\n";
        print "    modified:  ", $self->date_modified(),  "\n"
          if defined $self->date_modified();
    }
    print "\ndivider: -----------------------------\n";
    return $self;
}

# Goodbye cruel world!
sub DESTROY
{
    my __PACKAGE__ $self = shift;

    # The object won't be deallocated until all references to it are
    # gone.  Plus this allows the new() method to be called again.

    undef($VuXML);
    undef($self);
}

# Wipe out all vuln data -- reset to empty values
sub reset
{
    my __PACKAGE__ $self = shift;

    $self->_initialise(@_);

    return $self;
}

# Initialise per instance data.
sub _initialise
{
    my __PACKAGE__ $self = shift;

    $self->{save_text}        = undef;    # save input until this closing tag seen
    $self->{text_buffer}      = undef;
    $self->{parsed_data}      = {};
    $self->{database_updated} = 0;
    %{ $self->{parsed_data} } = (
        vid            => undef,     # Vulnerability ID (Scalar)
        cancelled      => undef,     # VID of superseding Vuln
        topic          => undef,     # One line summary of problem
        packages       => [],        # Affected package names and versions
        systems        => [],        # Affect OS name and versions
        description    => undef,     # xhtml -- several paras of details
        references     => [],        # URLs, CVE, etc. references
        date_discovery => undef,     # When discovered,
        date_entry     => undef,     # When entered into VuXML
        date_modified  => undef,     # Last time entry modified
        checksum       => undef,
        @_                           # Miscellaneous additions?
    );
    return $self;
}

sub parse_xml
{
    my __PACKAGE__ $self = shift;
    
    my $checksum = shift;

    $self->{checksum} = $checksum;
         
    $self->{xml_parser}->parse( $self->{input}, ProtocolEncoding => 'ISO-8859-1' );

    return $self;
}

sub update_database
{
    my __PACKAGE__ $self = shift;

    # Not interested in cancelled records

    $self->print_self();    # For debugging purposes
    
    # Only commit stuff related to FreeBSD.  Assume it's FreeBSD
    # related if no explicit <system> tag is given.

    return $self
      unless $self->systems() == 0
      || grep '/FreeBSD/', $self->systems() > 0;

    # Only interested in ports -- vulns to do with the base system
    # don't have package names listed.

    return $self
      unless $self->packages() > 0 || defined $self->cancelled();

    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    # Here is where the code goes to dump the data stored in this
    # object out into the database.  This is called once per vuln
    # listed in the vuln.xml file.
    #
    # $self->{db_handle}; is a database handle -- see DBI.pm
    #
    # %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

	my $FullInsert  = 1;
	my $MarkCommits = 0;

	if (defined $self->cancelled()) {
		# we do not insert cancelled vuln
		$FullInsert = 0;
		my $vuxml = FreshPorts::vuxml->new( $self->{db_handle} );

		# this will wipe the vuln and any references to it, including the commit_log_ports_vuxml table  
		$vuxml->DeleteByVID($self->vid());
	}

        print "Shall we update?\n";
	if ($self->{update_in_place} && !defined $self->cancelled()) {
		# updates in place are awkward... it gets complex.
		# let's just delete and then do a full insert

		my $vuxml = FreshPorts::vuxml->new( $self->{db_handle} );

		# this will wipe the vuln and any references to it, including the commit_log_ports_vuxml table  
		$vuxml->DeleteByVID($self->vid());
	}
	else
	{
	    print "no.  We are not updating\n";
	}

	if ($FullInsert) {
		my $vuxml_id = $self->update_database_vuxml(undef);
		$self->update_database_vuxml_affected  ($vuxml_id);
		$self->update_database_vuxml_references($vuxml_id);
		$self->{database_updated} = 1;
	}


	return $self;
}

sub DateLessThanDate {
	use Date::Calc qw( Date_to_Days );

	my $Date1 = shift;
	my $Date2 = shift;

	my ($Y1, $M1, $D1) = $Date1 =~ /(\d+)-(\d+)-(\d+)/;
	my ($Y2, $M2, $D2) = $Date2 =~ /(\d+)-(\d+)-(\d+)/;

	return Date_to_Days($Y1, $M1, $D1) < Date_to_Days($Y2, $M2, $D2);
}

sub RecentlyAdded {
	use Date::Calc qw( Today Add_Delta_Days Date_to_Days );

	my $Date = shift;

	my ($Y, $M, $D) = $Date =~ /(\d+)-(\d+)-(\d+)/;

	my ($TodayY, $TodayM, $TodayD) = Today();

	my ($TodayY2, $TodayM2, $TodayD2) = Add_Delta_Days($TodayY, $TodayM, $TodayD, -2);

	return Date_to_Days($TodayY2, $TodayM2, $TodayD2) < Date_to_Days($Y, $M, $D)
}


# now deprecated, we don't use this any more.  can be deleted.
sub vuxml_differs
{

	my __PACKAGE__ $self = shift;
	my $vuxml            = shift;

	my $differs = 0;  # for now, always different

	if (RecentlyAdded($vuxml->{date_entry}) || (defined($vuxml->{date_modified})
	                                   && RecentlyAdded($vuxml->{date_modified}))) {
		$differs = 1;
	}

	return $differs;
}

sub update_database_vuxml
{
	my __PACKAGE__ $self = shift;
	my $vuxml_org        = shift;

	use FreshPorts::vuxml;

	my $vuxml_id;
	
	print "into update_database_vuxml\n";

	my $vuxml = FreshPorts::vuxml->new( $self->{db_handle} );

	if (defined($vuxml_org)) {
		$vuxml->{id}     = $vuxml_org->{id};
		$vuxml->{status} = $vuxml_org->{status};
	}

	$vuxml->{vid}            = $self->vid();
	$vuxml->{topic}          = $self->topic();
	$vuxml->{description}    = $self->description();
	$vuxml->{date_discovery} = $self->date_discovery();
	$vuxml->{date_entry}     = $self->date_entry();
	$vuxml->{date_modified}  = $self->date_modified();
	$vuxml->{checksum}       = $self->{checksum};

	$vuxml_id = $vuxml->save();

	return $vuxml_id;
}

sub update_database_vuxml_affected
{
	my __PACKAGE__ $self = shift;
	my $vuxml_id         = shift;

	my $package_count = 0;

	use FreshPorts::vuxml_affected;
	use FreshPorts::vuxml_names;
	use FreshPorts::vuxml_ranges;

	my $vuxml_affected          = FreshPorts::vuxml_affected->new( $self->{db_handle} );
	my $vuxml_affected_names    = FreshPorts::vuxml_names->new   ( $self->{db_handle} );
	my $vuxml_affected_ranges   = FreshPorts::vuxml_ranges->new  ( $self->{db_handle} );

	my $vuxml_affected_names_id;

	for my $package ( $self->packages() ) {
        	$vuxml_affected->{vuxml_id} = $vuxml_id;
        	# when/if we start storing system vuxml information, this changes
        	$vuxml_affected->{type}     = 'package';

        	my $vuxml_affected_id = $vuxml_affected->save();

        	if ( $package->name() ) {
        	       	for my $name ( $package->name() ) {
        	       		$vuxml_affected_names->{vuxml_affected_id} = $vuxml_affected_id;
        	       		$vuxml_affected_names->{name}              = $name;

        	       		$vuxml_affected_names_id = $vuxml_affected_names->save();
        	       		$vuxml_affected_names->empty();
                        }
                 }

        if ( $package->category() ) {
            print "    category:\n";
            for my $category ( $package->category() ) {
                print "        category: $category\n";
            }
        }

        if ( $package->architecture() ) {
            print "    architecture:\n";
            for my $architecture ( $package->architecture() ) {
                print "        architecture: $architecture\n";
            }
        }

        if ( $package->range() ) {
            for my $range ( $package->range() ) {
                print $range->[0], ": ", $range->[1],
                  " " x ( 10 - length $range->[1] );
                if ( $range->[2] ) {
	                print $range->[2], ": ", $range->[3], "\n";
				}
                $vuxml_affected_ranges->{vuxml_affected_id} = $vuxml_affected_id;
                $vuxml_affected_ranges->{operator1}         = $range->[0];
                $vuxml_affected_ranges->{version1}          = $range->[1];
                $vuxml_affected_ranges->{operator2}         = $range->[2];
                $vuxml_affected_ranges->{version2}          = $range->[3];

                $vuxml_affected_ranges->save();
                $vuxml_affected_ranges->empty();
            }
        }

        $package_count++;
		$vuxml_affected->empty();
    }

    return $package_count;
}

sub update_database_vuxml_references
{
    my __PACKAGE__ $self = shift;
    my $vuxml_id         = shift;

    my $reference_count = 0;

    use FreshPorts::vuxml_references;

    my $vuxml_references = FreshPorts::vuxml_references->new( $self->{db_handle} );

    foreach my $i ( $self->references() ) {
        print "    ", $i->[0], ":", " " x ( 10 - length( $i->[0] ) ),
          $i->[1], "\n";
        $vuxml_references->{vuxml_id}  = $vuxml_id;
        $vuxml_references->{type}      = $i->[0];
        $vuxml_references->{reference} = $i->[1];

        my $vuxml_references_id = $vuxml_references->save();

        $reference_count++;

        $vuxml_references->empty();
    }

    return $reference_count;
}

# Accessor methods

# Scalar value instance variables

for my $slot (
    qw(vid cancelled topic description date_discovery date_entry date_modified))
{

    no strict qw(refs);    # need a symbolic ref to a typeglob
    *$slot = sub {
        my __PACKAGE__ $self = shift;

        $self->{parsed_data}->{$slot} = shift if @_;
        return $self->{parsed_data}->{$slot};
    };
}

# Array valued instance variables

# i) References
#
# Stored as an array of pairs of values:
#
# [
#   [ FREEBSDPR, "ports/64777" ],
#   [ CVENAME,   "CAN-2004-0777" ], ...
# ]

# get/set all references at once.  Should be passed an even number of
# arguments, alternating one of the known types with the reference
# values, or an Nx2 array as stored internally.

sub references
{
    my __PACKAGE__ $self = shift;
    my $r;
    my $v;

    while (@_) {
        if ( ref( $_[0] ) eq 'ARRAY' ) {
            ( $r, $v ) = @{ shift() };
        } else {
            $r = shift();
            $v = shift();
        }

        croak "references(): Unknown reference type \"$r\""
          unless $r =~ $self->{_known_ref_types};
        croak "references(): Missing reference value"
          unless defined($v);

        push @{ $self->{parsed_data}->{references} }, [ $r, $v ];
    }
    return @{ $self->{parsed_data}->{references} };
}

# Get/Set (reference, value) at specific index:
sub reference_by_index
{
    my __PACKAGE__ $self = shift;
    my $i = shift;
    my $r;
    my $v;

    if (@_) {
        if ( ref( $_[0] ) eq 'ARRAY' ) {
            ( $r, $v ) = @{ shift() };
        } else {
            $r = shift();
            $v = shift();
        }

        croak "reference_by_index(): Unknown reference type \"$r\""
          unless $r =~ $self->{_known_ref_types};
        croak "reference_by_index(): Missing reference value"
          unless defined($v);

        $self->{parsed_data}->{references}[$i] = [ $r, $v ];
    }
    return @{ $self->{parsed_data}->{references}[$i] };
}

# Push reference, value pairs onto the end of the stack
sub references_push
{
    my __PACKAGE__ $self = shift;
    my $r;
    my $v;

    croak "references_push(): method takes two arguments"
      unless ( @_ >= 2 );
    $r = shift;
    $v = shift;
    croak "references_push(): Unknown reference type \"$r\""
      unless $r =~ $self->{_known_ref_types};
    croak "references_push(): Missing reference value"
      unless defined($v);

    push @{ $self->{parsed_data}->{references} }, [ $r, $v ];

    return $self;
}

sub references_shift
{
    my __PACKAGE__ $self = shift;

    return @{ shift @{ $self->{parsed_data}->{references} } };
}

#
# Temporarily switch packages to create some objects to hold
# the <package> and the <system> parsed data
#
{

    package FreshPorts::VuXML::Affects;

    # For packages, systems values internal data will be stored as an
    # array of entries (corresponding to the <package> or <system>
    # tagged bits) which are objects of class
    # FreshPorts::VuXML::Affects

    sub new
    {
        my $caller = shift;
        my $self;
        my $class = ref($caller) || $caller || __PACKAGE__;

        $self = {
            name            => [],
            range           => [],
            category        => [],
            architecture    => [],
            _known_op_types => qr/^(lt|gt|le|ge|eq)$/,
        };
        return bless $self, $class;
    }

    # Print out the contents of an <affects> region
    sub print_self
    {
        my __PACKAGE__ $self = shift;

        if ( $self->name() ) {
            for my $name ( $self->name() ) {
                print "    $name:\n";
            }
        }

        if ( $self->category() ) {
            print "    category:\n";
            for my $category ( $self->category() ) {
                print "        category: $category\n";
            }
        }

        if ( $self->architecture() ) {
            print "    architecture:\n";
            for my $architecture ( $self->architecture() ) {
                print "        architecture: $architecture\n";
            }
        }

        if ( $self->range() ) {
            for my $range ( $self->range() ) {
                print " " x 15;
                print $range->[0], ": ", $range->[1],
                  " " x ( 10 - length $range->[1] );
                if ( $range->[2] ) {
	                print $range->[2], ": ", $range->[3], "\n";
				}
            }
        }

        return $self;
    }

    # Bulk creation of accessor methods
    for my $slot (qw(name category architecture)) {
        my $slot_by_index = "${slot}_by_index";
        my $slot_push     = "${slot}_push";
        my $slot_shift    = "${slot}_shift";

        no strict qw(refs);

        # Get/set the whole array at once
        *$slot = sub {
            my __PACKAGE__ $self = shift;

            @{ $self->{$slot} } = @_ if (@_);
            return @{ $self->{$slot} };
        };

        # Get/set the value at a particular array index
        *$slot_by_index = sub {
            my __PACKAGE__ $self = shift;
            my $i = shift;

            $self->{$slot}[$i] = shift if (@_);
            return $self->{$slot}[$i];
        };

        # Add a new value to the end of the array
        *$slot_push = sub {
            my __PACKAGE__ $self = shift;
            push @{ $self->{$slot} }, shift;
            return $self;
        };

        # Pull the first value from the beginning of the array
        *$slot_shift = sub {
            my __PACKAGE__ $self = shift;
            return shift @{ $self->{$slot} };
        };
    }

    # The 'range' data is special:  consisting of one or more 4 valued
    # arrays giving the version number ranges between which the vulnerability
    # applies.  Where the range is one-sided some elements will be left
    # undefined.
    #
    # eg from vid="0c4d5973-f2ab-11d8-9837-000c41e2cdad"
    #
    #   [
    #     "mysql-scripts",
    #      [ undef, undef, _LE,   "3.23.58" ],
    #      [ _GT,   "4",   _LE,   "4.0.20"  ],
    #      [ _GT,   "4.1", _LE,   "4.1.3"   ],
    #      [ _GT,   "5",   _LE,   "5.0.0_1" ],
    #   ],
    #

    sub range
    {
        my __PACKAGE__ $self = shift;
        my $lop;
        my $lver;
        my $rop;
        my $rver;

        while (@_) {
            if ( ref( $_[0] ) eq 'ARRAY' ) {
                ( $lop, $lver, $rop, $rver ) = @{ shift() };
            } else {
                $lop  = shift;    # Can be undef
                $lver = shift;    # Can be undef
                $rop  = shift;
                $rver = shift;
            }
            Carp ::croak "range(): Unknown LHS operator type \"$lop\""
              unless ( !defined($lop) || $lop =~ $self->{_known_op_types} );
            Carp::croak "range(): Unknown RHS operator type \"$rop\""
              unless $rop =~ $self->{_known_op_types};
            Carp::croak "range(): Missing version number"
              unless defined($rver);

            push @{ $self->{range} }, [ $lop, $lver, $rop, $rver ];
        }
        return @{ $self->{range} };
    }

    sub range_by_index
    {
        my __PACKAGE__ $self = shift;
        my $i = shift;
        my $lop;
        my $lver;
        my $rop;
        my $rver;

        if (@_) {
            if ( ref( $_[0] ) eq 'ARRAY' ) {
                ( $lop, $lver, $rop, $rver ) = @{ shift() };
            } else {
                $lop  = shift;    # Can be undef
                $lver = shift;    # Can be undef
                $rop  = shift;
                $rver = shift;
            }

            Carp::croak "range_by_index(): Unknown LHS operator type \"$lop\""
              unless !defined($lop) || $lop =~ $self->{_known_op_types};
            Carp::croak "range_by_index(): Unknown RHS operator type \"$rop\""
              unless $rop =~ $self->{_known_op_types};
            Carp::croak "range_by_index(): Missing version number"
              unless defined($rver);

            $self->{range}[$i] = [ $lop, $lver, $rop, $rver ];

        }
        return @{ $self->{range}[$i] };
    }

    sub range_push
    {
        my __PACKAGE__ $self = shift;
        my $lop;
        my $lver;
        my $rop;
        my $rver;

        Carp::croak "range_push(): method takes four arguments"
          unless ( @_ >= 4 );

        $lop  = shift;
        $lver = shift;
        $rop  = shift;    # can be undef
        $rver = shift;    # can be undef

        Carp::croak "range_push(): Unknown LHS operator type \"$lop\""
          unless !defined($rop) || $rop =~ $self->{_known_op_types};
        Carp::croak "range_push(): Unknown RHS operator type \"$rop\""
          unless $lop =~ $self->{_known_op_types};
        Carp::croak "range_push(): Missing version number"
          unless defined($lver);

        push @{ $self->{range} }, [ $lop, $lver, $rop, $rver ];

        return $self;
    }

    sub range_shift
    {
        my __PACKAGE__ $self = shift;

        return @{ shift @{ $self->{range} } };
    }

}

for my $slot (qw(packages systems)) {
    my $slot_by_index = "${slot}_by_index";
    my $slot_push     = "${slot}_push";
    my $slot_shift    = "${slot}_shift";

    no strict qw(refs);    # need a symbolic ref to a typeglob

    # Get/set the whole array at once
    *$slot = sub {
        my __PACKAGE__ $self = shift;

        while (@_) {
            my $p;

            # Entries in this array are FreshPorts::VuXML::Affects
            # objects
            $p = shift;

            croak "$slot(): Argument is of the wrong object type"
              unless ( $p->isa("FreshPorts::VuXML::Affects") );
            push @{ $self->{parsed_data}->{$slot} }, $p;
        }
        return @{ $self->{parsed_data}->{$slot} };
    };

    # Get/set the value at a particular array index
    *$slot_by_index = sub {
        my __PACKAGE__ $self = shift;
        my $i = shift;

        if (@_) {
            croak "$slot_by_index(): Argument is of the wrong object type"
              unless ( $_[0]->isa("FreshPorts::VuXML::Affects") );
            $self->{parsed_data}->{$slot}[$i] = shift;
        }
        return $self->{parsed_data}->{$slot}[$i];
    };

    # Add a new value to the end of the array
    *$slot_push = sub {
        my __PACKAGE__ $self = shift;

        croak "$slot_push(): method takes one argument"
          unless ( @_ >= 1 );
        croak "$slot_push(): Argument is of the wrong object type"
          unless ( $_[0]->isa("FreshPorts::VuXML::Affects") );

        push @{ $self->{parsed_data}->{$slot} }, shift @_;

        return $self;
    };

    # Pull the first value from the start of the array
    *$slot_shift = sub {
        my __PACKAGE__ $self = shift;
        return shift @{ $self->{parsed_data}->{$slot} };
    };
}

# Select which type of <affects> entry we're dealing with: either
# package or system
sub new_target
{
    my __PACKAGE__ $self = shift;
    my $target = shift;

    if ( $target eq "package" ) {
        push @{ $self->{parsed_data}->{packages} },
          FreshPorts::VuXML::Affects::new();
        $self->{_target} = $self->{parsed_data}->{packages};
    } elsif ( $target eq "system" ) {
        push @{ $self->{parsed_data}->{systems} },
          FreshPorts::VuXML::Affects::new();
        $self->{_target} = $self->{parsed_data}->{systems};
    } else {
        croak "new_target(): unknown target type \"$target\"";
    }
    return $self->{_target}[-1];
}

sub target
{
    my __PACKAGE__ $self = shift;
    return $self->{_target}[-1];
}

# Take arguments two at a time, and fill into _range_buffer so that
# defined values are packed at the top of the array.
sub range_buffer
{
    my __PACKAGE__ $self = shift;

    if (@_) {
        my $op  = shift;
        my $ver = shift;

        if ( defined( $self->{_range_buffer}[0] ) ) {
            $self->{_range_buffer}[2] = $op;
            $self->{_range_buffer}[3] = $ver;
        } else {
            $self->{_range_buffer}[0] = $op;
            $self->{_range_buffer}[1] = $ver;
        }
    }
    return @{ $self->{_range_buffer} };
}

sub range_buffer_clear
{
    my __PACKAGE__ $self = shift;

    $self->{_range_buffer} = [ undef, undef, undef, undef ];
    return $self;
}

=item Framework of vuxml-12 (beta) format

	Items marked * are considered terminals ie. contain no other
	interesting tags. In the case of <description> the content is a
	chunk of XHTML, but we dont care to parse that out.

	
    >vuxml

    >vuxml>vuln   -- attr: vid

    >vuxml>vuln>cancelled  --attr: superseded
    
    >vuxml>vuln>topic *

    >vuxml>vuln>affects

    >vuxml>vuln>affects>package

    >vuxml>vuln>affects>package>name *
    >vuxml>vuln>affects>package>architecture *
    >vuxml>vuln>affects>package>category *
    >vuxml>vuln>affects>package>range
    >vuxml>vuln>affects>package>range>lt *
    >vuxml>vuln>affects>package>range>gt *
    >vuxml>vuln>affects>package>range>le *
    >vuxml>vuln>affects>package>range>ge *
    >vuxml>vuln>affects>package>range>eq *

    >vuxml>vuln>affects>system>name *
    >vuxml>vuln>affects>system>architecture *
    >vuxml>vuln>affects>system>category *
    >vuxml>vuln>affects>system>range
    >vuxml>vuln>affects>system>range>lt *
    >vuxml>vuln>affects>system>range>gt *
    >vuxml>vuln>affects>system>range>le *
    >vuxml>vuln>affects>system>range>ge *
    >vuxml>vuln>affects>system>range>eq *

    >vuxml>vuln>description *

    >vuxml>vuln>references
    >vuxml>vuln>references>url *
    >vuxml>vuln>references>mlist *
    >vuxml>vuln>references>cvename *
    >vuxml>vuln>references>bid *
    >vuxml>vuln>references>certsa *
    >vuxml>vuln>references>certvu *
    >vuxml>vuln>references>uscertsa *
    >vuxml>vuln>references>uscertta *
    >vuxml>vuln>references>freebsdsa *
    >vuxml>vuln>references>freebsdpr *

    >vuxml>vuln>dates
    >vuxml>vuln>dates>discovery *
    >vuxml>vuln>dates>entry *
    >vuxml>vuln>dates>modified *

=cut

# Comparison operators for package version numbers
sub _LT { 'lt' }    # <
sub _GT { 'gt' }    # >
sub _LE { 'le' }    # <=
sub _GE { 'ge' }    # >=
sub _EQ { 'eq' }    # =

# From version 12beta -- add <architecture> and <category> support as
# labels for sub-entries of <affected><package> or <affected><system>
sub ARCHITECTURE { 'architecture' }
sub CATEGORY     { 'category' }

# Reference types:
sub URL       { 'url' }          # Default
sub MLIST     { 'mlist' }        # Archived mailing list posting
sub CVENAME   { 'cvename' }      # Common Vulnerabilities and Exposures
sub BID       { 'bid' }          # SecurityFocus BugID
sub CERTSA    { 'certsa' }       # US-CERT (formerly CERT/CC) security advisory
sub CERTVU    { 'certvu' }       # US-CERT (formerly CERT/CC) vulnerability note
sub USCERTSA  { 'uscertsa' }     # US-CERT Cyber Security Alert
sub USCERTTA  { 'uscertta' }     # US-CERT Technical Cyber Security Alert
sub FREEBSDSA { 'freebsdsa' }    # FreeBSD security advisory
sub FREEBSDPR { 'freebsdpr' }    # FreeBSD problem report

# Handlers -- callbacks from the parser (Nb. these prototypes actually
# have no effect, since these subs are called indirectly, via a
# reference.  They're for documentation purposes only.)

#
# Starting <tag> operations
#

sub handle_start ($$;@)
{
    my $expat   = shift;
    my $element = shift;

    # Start tag handling -- get attributes, etc.
    &{ $VuXML->{start_handlers}->{$element} }(@_)
      if ( defined $VuXML->{start_handlers}->{$element} );

    # If we're in text saving mode, save this start tag, with any
    # attrs: Note: we never save any <tags>, just the contents, other
    # than what's part of the xhtml included inside the <description>
    # tag.

    if ( defined( $VuXML->{save_text} )) {
        if ( $VuXML->{save_text} eq 'description' ) {
            $VuXML->{text_buffer} .= '<' . $element;
            while (@_) {
                $VuXML->{text_buffer} .= ' ' . shift() . '="' . shift() . '"';
            }
            $VuXML->{text_buffer} .= '>';
        }
    }

    # If this is one of the tags that contains content we're
    # interested in saving set a flag to signal that the text
    # etc. should be saved until the matching end tag.

    if (
        $element =~ m/
		  ^( topic        |
			 name         |
			 architecture |
			 category     |
			 lt           |
			 gt           |
			 le           |
			 ge           |
			 eq           |
			 description  |
			 url          |
			 mlist        |
			 cvename      |
			 bid          |
			 certsa       |
			 certvu       |
			 uscertsa     |
			 uscertta     |
			 freebsdsa    |
			 freebsdpr    |
			 discovery    |
			 entry        |
			 modified     )$
		/x
      )
    {
        $VuXML->{save_text} = $element;
    }
    return;
}

sub handle_start_vuln (@)
{
    my %attrs = @_;

    $VuXML->reset();    # Start of a new vulnerability
    $VuXML->vid( $attrs{vid} );
}

sub handle_start_cancelled (@)
{
    my %attrs = @_;

    if ( defined $attrs{superseded} ) {
        $VuXML->cancelled( $attrs{superseded} );
    } else {
        $VuXML->cancelled("");
    }
}

sub handle_start_package (@)
{
    $VuXML->new_target('package');
}

sub handle_start_system (@)
{
    $VuXML->new_target('system');
}

sub handle_start_range (@)
{
    $VuXML->range_buffer_clear();
}

#
# Char operations
#

sub handle_char ($$)
{
    my $expat = shift;
    my $text  = shift;

    # If we're in text saving mode, save this text.
    if ( $VuXML->{save_text} ) {
        $VuXML->{text_buffer} .= $text;
    }

    return;
}

#
# Closing </tag> operations
#

sub handle_end ($$)
{
    my $expat   = shift;
    my $element = shift;

    # Call the handler for this element via dispatch table.
    &{ $VuXML->{end_handlers}->{$element} }()
      if defined $VuXML->{end_handlers}->{$element};

    # If this is the matching closing tag, stop saving the text and
    # save it into the $VuXML object.

    if ( defined( $VuXML->{save_text} )) {
       if ( $element eq $VuXML->{save_text} ) {
           $VuXML->{save_text}   = undef;    # Done saving.
           $VuXML->{text_buffer} = undef;
       }
    } 

    # If we're in text saving mode, save this end tag
    if ( $VuXML->{save_text} ) {
        $VuXML->{text_buffer} .= '</' . $element . '>';
    }

    # End of the vuln element -- push the data out to the database.
    if ( $element eq 'vuln' ) {
        # TODO this is where we could check the database to see if this vuln is identical to an existing vuln...
        # store a hash, compare, and process only if changed...
        # and then you'd have to figure out a way to process only the changed vulns...
        $VuXML->update_database();
    }
    return;
}

sub handle_end_topic ()
{
    $VuXML->topic( $VuXML->{text_buffer} );
}

sub handle_end_name ()
{
    $VuXML->target()->name_push( $VuXML->{text_buffer} );
}

sub handle_end_architecture ()
{
    $VuXML->target()->architecture_push( $VuXML->{text_buffer} );
}

sub handle_end_category ()
{
    $VuXML->target()->category_push( $VuXML->{text_buffer} );
}

sub handle_end_range ()
{
    $VuXML->target()->range_push( $VuXML->range_buffer() );
}

sub handle_end_lt ()
{
    $VuXML->range_buffer( _LT, $VuXML->{text_buffer} );
}

sub handle_end_gt ()
{
    $VuXML->range_buffer( _GT, $VuXML->{text_buffer} );
}

sub handle_end_le ()
{
    $VuXML->range_buffer( _LE, $VuXML->{text_buffer} );
}

sub handle_end_ge ()
{
    $VuXML->range_buffer( _GE, $VuXML->{text_buffer} );
}

sub handle_end_eq ()
{
    $VuXML->range_buffer( _EQ, $VuXML->{text_buffer} );
}

sub handle_end_description ()
{

    # To save space in the DB? Crunch whitespace in the
    # description: of course, this will screw up any <pre>
    # marked-up text...
    ## $VuXML->{text_buffer} =~ s/\s+/ /g;

    # Strip <body> and </body> tags.
    $VuXML->{text_buffer} =~ s:</?body[^>]*>::g;
    $VuXML->description( $VuXML->{text_buffer} );
}

sub handle_end_url ()
{
    $VuXML->references_push( URL, $VuXML->{text_buffer} // '' );
}

sub handle_end_mlist ()
{
    $VuXML->references_push( MLIST, $VuXML->{text_buffer} // '' );
}

sub handle_end_cvename ()
{
    $VuXML->references_push( CVENAME, $VuXML->{text_buffer} // '' );
}

sub handle_end_bid ()
{
    $VuXML->references_push( BID, $VuXML->{text_buffer} // '' );
}

sub handle_end_certsa ()
{
    $VuXML->references_push( CERTSA, $VuXML->{text_buffer} // '' );
}

sub handle_end_certvu ()
{
    $VuXML->references_push( CERTVU, $VuXML->{text_buffer} // '' );
}

sub handle_end_uscertsa ()
{
    $VuXML->references_push( USCERTSA, $VuXML->{text_buffer} // '' );
}

sub handle_end_uscertta ()
{
    $VuXML->references_push( USCERTTA, $VuXML->{text_buffer} // '' );
}

sub handle_end_freebsdsa ()
{
    $VuXML->references_push( FREEBSDSA, $VuXML->{text_buffer} // '' );
}

sub handle_end_freebsdpr ()
{
    $VuXML->references_push( FREEBSDPR, $VuXML->{text_buffer} // '' );
}

sub handle_end_discovery ()
{
    $VuXML->date_discovery( $VuXML->{text_buffer} );
}

sub handle_end_entry ()
{
    $VuXML->date_entry( $VuXML->{text_buffer} );
}

sub handle_end_modified ()
{
    $VuXML->date_modified( $VuXML->{text_buffer} );
}

1;

#
# That's All Folks!
#
