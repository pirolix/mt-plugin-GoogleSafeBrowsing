package MT::GoogleSafeBrowsing::BlackHash;

use strict;

use base qw( MT::Object );
__PACKAGE__->install_properties({
    column_defs => {
        'key' => 'string(32) not null',
    },
    indexes => {
        'key' => 1,
    },
    datasource => 'gsb_black_hash',
    primary_key => 'key',
});

sub class_label {
    'GoogleSafeBrowsing Black Hash';
}

1;