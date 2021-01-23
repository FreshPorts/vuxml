#!/usr/local/bin/perl
#
# $Id: process_vuxml.pl,v 1.6 2013-01-16 15:37:57 dan Exp $
#
# Copyright (c) 2001-2012 DVL Software
#
# much of this file is based on contributions from Matthew Seamon
#

# @{#} $Id: process_vuxml.pl,v 1.6 2013-01-16 15:37:57 dan Exp $
#
# Split up the vuln.xml file into sections for individual
# vulnerabilities.  Save into files using the vid guid field as name.
# Calculate SHA256 checksum for the XML snippet and write out to an
# index file.

#use 5.10.1;
use strict;
use warnings;
use XML::DOM::XPath;
use Encode;
use Digest::SHA qw(sha256_hex);
use autodie qw(:default);
use IO::File;
use Getopt::Long;

use FreshPorts::database;
use FreshPorts::vuxml;
use FreshPorts::vuxml_parsing;
use FreshPorts::vuxml_mark_commits;

my $filename;

# From https://perldoc.perl.org/perlunifaq.html#What-is-a-%22wide-character%22%3f
# to handle: Wide character in print at /usr/local/lib/perl5/site_perl/FreshPorts/vuxml_parsing.pm line 234, <> chunk 1.\n

binmode STDOUT, ":encoding(UTF-8)";

#use feature qw(switch);


# Reads vuln.xml on stdin * NOT ANY MORE
GetOptions ('filename:s' => \$filename);

print $filename;

my $start = time;

print 'process_vuxml.pl finishes' . "\n";


MAIN:
{
    my %vulns;
    my @vulns;

    my $parser = new XML::DOM::Parser;
    my $doc = $parser->parsefile ($filename);
    
    my $dbh;
    $dbh = FreshPorts::Database::GetDBHandle();
    if ($dbh->{Active}) {
        my $fh = IO::File->new();
        my $vuxml = FreshPorts::vuxml->new( $dbh );
          
        eval {
            for my $node ($doc->findnodes('/vuxml/vuln'))
            {
                my $vid  = $node->getAttributeNode('vid')->getValue();
                my $csum = sha256_hex(Encode::encode_utf8($node->toString));
                print  $vid . " " . $csum . "\n";

                # fetch the checksum from the database
                my $checksum = $vuxml->FetchChecksumByVID($vid);

                my $updateRequired = 1;
                if (defined($checksum)) {

                    if ($csum eq $checksum && 1) {
                        $updateRequired = 0;
                    }

                    print "vuln check: $vid = '$csum' '$checksum'\n";
                } else {
                    print "vuln check: $vid = '$csum' not found\n";
                }

                if ($updateRequired) {
                    if ($fh->open(\$node->toString(), '<')) {
                        my $p = FreshPorts::vuxml_parsing->new(Stream        => $fh,
                                                               DBHandle      => $dbh,
                                                               UpdateInPlace => 1);

                        $p->parse_xml($csum);

                        if ($p->database_updated()) {
                            print "yes, the database was updated\n";
                        } else {
                            print "no, the database was NOT updated\n";
                            next;
                        }

                        $fh->close;
                    } # if ($fh->open

                    # process $vulns{$v} via vuxml_processing

                    print 'invoking vuxml_mark_commits with ' . $vid . "\n";
                    my $CommitMarker = FreshPorts::vuxml_mark_commits->new(DBHandle => $dbh,
                                                                           vid      => $vid);
                    print 'invoking ProcessEachRangeRecord'. "\n";
                    my $i = $CommitMarker->ProcessEachRangeRecord();

                    print 'invoking ClearCachedEntries' . "\n";
                    $CommitMarker->ClearCachedEntries($vid);
                    
                } # if ($updateRequired)
            } # for my $node
        }; # eval

        print 'finished with eval()' . "\n";

        # if something went wrong in the eval, abort and don't do a commit
        if ($@) {
            print "We've got a problem.";
            print "$0: $@\n";
            FreshPorts::CommitterOptIn::RecordErrorDetails("error processing vuxml", $0);
            die "$0: $@\n";
        }

        print "committing\n";
        $dbh->commit();

        $dbh->disconnect();
    } # if ($dbh->{Active}
} # MAIN

my $end = time();

print "Total time: " . ($end - $start) . " seconds\n";


#
# That's All Folks!
#

print 'process_vuxml.pl finishes' . "\n";
