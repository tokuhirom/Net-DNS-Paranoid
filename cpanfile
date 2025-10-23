requires 'Class::Accessor::Lite', '0.05';
requires 'Net::DNS', '0.68';
requires 'IPv6::Address', '0.208';
requires 'parent';
requires 'perl', '5.008008';

on build => sub {
    requires 'Test::More', '0.98';
};
