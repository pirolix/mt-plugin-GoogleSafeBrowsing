package MT::Plugin::OMV::GoogleSafeBrowsing;

use strict;
use MT 4;
use MT::Log;
use MT::JunkFilter qw( ABSTAIN );
use MT::GoogleSafeBrowsing::BlackHash;
use MT::GoogleSafeBrowsing::MalwareHash;
use LWP::UserAgent;
use Digest::MD5;

use constant URL_SAFE       => 0;
use constant URL_BLACK      => 1;
use constant URL_MALWARE    => 2;

use vars qw( $MYNAME $VERSION $SCHEMA_VERSION );
$MYNAME = 'GoogleSafeBrowsing';
$VERSION = '0.03';
$SCHEMA_VERSION = '0.0102';


use base qw( MT::Plugin );
my $plugin = __PACKAGE__->new({
        name => $MYNAME,
        id => lc $MYNAME,
        key => lc $MYNAME,
        version => $VERSION,
        schema_version => $SCHEMA_VERSION,
        author_name => 'Open MagicVox.net',
        author_link => 'http://www.magicvox.net/',
#        doc_link => 'http://www.magicvox.net/',
        description => <<HTMLHEREDOC,
<__trans phrase="Check whether URL is not malwared or black-listed by Google Safe Browsing API.">
HTMLHEREDOC
        system_config_template => 'tmpl/config.tmpl',
        settings => new MT::PluginSettings([
            ['apikey', { Default => undef, Scope => 'system' }],
            ['black_hash_major', { Default => 1, Scope => 'system' }],
            ['black_hash_minor', { Default => -1, Scope => 'system' }],
            ['black_hash_num', { Default => 0, Scope => 'system' }],
            ['malware_hash_major', { Default => 1, Scope => 'system' }],
            ['malware_hash_minor', { Default => -1, Scope => 'system' }],
            ['malware_hash_num', { Default => 0, Scope => 'system' }],
            ['last_updated', { Default => 0, Scope => 'system' }],
        ]),
});
MT->add_plugin( $plugin );

sub instance { $plugin; }

### Registry
sub init_registry {
    my $plugin = shift;
    $plugin->registry({
        object_types => {
            gsb_black_hash => 'MT::GoogleSafeBrowsing::BlackHash',
            gsb_malware_hash => 'MT::GoogleSafeBrowsing::MalwareHash',
        },
        tasks => {
            $MYNAME => {
                label => 'Update malware/black hash table',
                frequency => 60 * 15,
                code => \&_task_update_table,
            },
        },
        junk_filters => {
            $MYNAME => {
                label => "$MYNAME URL Check",
                code => \&_hdlr_filter,
            },
        },
    });
}



### Update hash tables by periodical task
sub _task_update_table {
    my ($cb) = @_;

    # Retrieve hash list with network
    my $apikey = &instance->get_config_value ('apikey')
        or return; # not yet configured, do nothing.
    my $version = sprintf '%s:%d:%d,%s:%d:%d',
            'goog-black-hash',
            &instance->get_config_value ('black_hash_major'),
            &instance->get_config_value ('black_hash_minor'),
            'goog-malware-hash',
            &instance->get_config_value ('malware_hash_major'),
            &instance->get_config_value ('malware_hash_minor');
    my %param = (
        client => 'api', apikey => $apikey, version => $version,
    );
    my $url = 'http://sb.google.com/safebrowsing/update?'.
            join '&', map { $_. '='. $param{$_} } keys %param;
    my $ua = LWP::UserAgent->new
        or return; # error
    $ua->agent ("$MYNAME/$VERSION (". $plugin->doc_link. ")");
    my $res = $ua->get ($url)
        or return; # error
    my $buffer = $res->content
        or return; # error

    my $model;
    my ($black_hash_major, $black_hash_minor);
    my ($malware_hash_major;, $malware_hash_minor);
    my $count_add = 0;
    my $count_remove = 0;
    foreach (split /[\r\n]/, $buffer) {
        if ($model && /^([+-])([0-9a-fA-F]{32})/) {
            my $key = lc $2;
            if ($1 eq '+') {
                my $obj = $model->load ({ key => $key });
                unless ($obj) {
                    $obj = $model->new;
                    $obj->key ($key);
                    $obj->save;
                }
                $count_add++;
            }
            elsif ($1 eq '-') {
                map { $_->remove } $model->load ({ key => $key });
                $count_remove++;
            }
        }
        elsif (/^\[goog-black-hash (\d+)\.(\d+)/) {
            $model = 'MT::GoogleSafeBrowsing::BlackHash';
            ($black_hash_major, $black_hash_minor) = ($1, $2);
        }
        elsif (/^\[goog-malware-hash (\d+)\.(\d+)/) {
            $model = 'MT::GoogleSafeBrowsing::MalwareHash';
            ($malware_hash_major, $malware_hash_minor) = ($1, $2);
        }
        sleep 0;
    }
    # Logging
    if ($count_add || $count_remove) {
        MT->log({
            class => 'plugin',
            level => MT::Log::INFO(),
            message => MT->translate ("$MYNAME: Add [_1] hashes, remove [_2] hashes.", $count_add, $count_remove),
        });

        &instance->set_config_value ('last_updated', time);
        &instance->set_config_value ('black_hash_num', MT::GoogleSafeBrowsing::BlackHash->count());
        &instance->set_config_value ('malware_hash_num', MT::GoogleSafeBrowsing::MalwareHash->count());

        &instance->set_config_value ('black_hash_major', $black_hash_major);
        &instance->set_config_value ('black_hash_minor', $black_hash_minor);
        &instance->set_config_value ('malware_hash_major', $malware_hash_major);
        &instance->set_config_value ('malware_hash_minor', $malware_hash_minor);
    }
}



###
sub _hdlr_filter {
    my ($obj) = @_;

    my $text = _get_text ($obj);
    my @urls = _get_urls ($text);
    foreach (@urls) {
        my $ret = _check_url ($_);
        if ($ret == URL_BLACK) {
            return (-5, &instance->translate ('Object contains the [_1] URL', 'black-listed'));
        }
        elsif ($ret == URL_MALWARE) {
            return (-5, &instance->translate ('Object contains the [_1] URL', 'malware-listed'));
        }
    }
    return (ABSTAIN);
}

### Object into text
sub _get_text {
    my ($obj) = @_;
    if (UNIVERSAL::isa ($obj, 'MT::Comment')) {
        return join "\n", map { $obj->$_ || '' } qw(
            author email url text ip
        );
    }
    elsif (UNIVERSAL::isa ($obj, 'MT::TBPing')) {
        return join "\n", map { $obj->$_ || '' } qw(
            blog_name title excerpt source_url ip
        );
    }
    return '';
}

### Search URL in text
sub _get_urls {
    my ($text) = @_;

    my @urls;
    while ($text =~ s!(?:^|\s)(https?://\S+)!!s) {
        push @urls, $;
    }
    @urls;
}

### Check URL
sub _check_url {
    my ($url) = @_;
    my @urls = _canonical_urls ($url);
    foreach (@urls) {
        my $hash = lc Digest::MD5::md5_hex ($_);
        return URL_BLACK if MT::GoogleSafeBrowsing::BlackHash->load({ key => $hash });
        return URL_MALWARE if MT::GoogleSafeBrowsing::MalwareHash->load({ key => $hash });
    }
    return URL_SAFE;
}

### Make uel list with canocalized
sub _canonical_urls {
    my ($url) = @_;

    # @see http://code.google.com/intl/ja/apis/safebrowsing/developers_guide.html#Canonicalization
    $url = lc $url;
    $url =~ s!^\s+|\s+$!!g;         # omit leading and trailing spaces
    $url =~ s!^\.+|\.+$!!g;         # omit leading and trailing dots
    $url =~ s!\.+!.!g;              # consecutive dots -> single dot
    my ($domain, $path, $query) = $url =~ m!^\w+://([^/]+)(/[^\?]*)?(\?.*)?$!;
    $domain =~ s!\:\d+/!/!;         # omit port number
    $path =~ s!/\./!/!g;            # omit /./ -> /
    $path =~ s!/[^/]+/\.\./!/!g;    # omit /abc/../ -> /

    # @see http://code.google.com/intl/ja/apis/safebrowsing/developers_guide.html#PerformingLookups
    my @urls;
    my @domains = split /\./, $domain;
    my @pathes = split /\//, $path;
    do {
        for (0..$#pathes) {
            $domain  = join '.', @domains;
            $domain .= join '/', @pathes[0..$_];
            if ($_ == $#pathes && $query) {
                push @urls, $domain. $query;
            } else {
                $domain .= '/';
            }
            push @urls, $domain;
        }
        shift @domains while (6 < scalar @domains);
        shift @domains;
    } while (1 < scalar @domains);

    @urls;
}

1;