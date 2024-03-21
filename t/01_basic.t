#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use Path::Tiny qw(path tempfile);
use Capture::Tiny qw(capture_merged);
use Crypt::ECDH_ES qw(ecdhes_generate_key ecdhes_encrypt);

my $plain = 'This is plain text!';

my($public, $private) = ecdhes_generate_key();

my $crypted_hex = unpack('H*', ecdhes_encrypt($public, $plain));

my $fpriv = tempfile(DIR => $Bin);
$fpriv->spew(unpack('H*', $private));

my $src = "$Bin/../src/ecdh_es_decrypt.c";
my $exe = $^O eq 'MSWin32' ? 'ecdh_es_decrypt.exe' :'ecdh_es_decrypt';
my $dexe = path($Bin, "../bin/debug_$exe")->touchpath;
my $pexe = path($Bin, "../bin/$exe")->touchpath;

# debug executable
my($out, $rc) = capture_merged{
    system(qq(gcc "$src" -o "$dexe" -DDEBUG));
    $? >> 8;
};
ok(!$rc, 'compile ok') or diag $out;

($out) = capture_merged{
    system(qq("$dexe" "$fpriv" "$crypted_hex"));
};
like($out, qr/\Q$plain\E$/, 'decrypt ok') or diag $out;

($out) = capture_merged{
    system(qq("$dexe" "$fpriv" "ecdhes$crypted_hex"));
};
like($out, qr/\Q$plain\E$/, 'prefixed decrypt ok') or diag $out;

# prod
($out, $rc) = capture_merged{
    system(qq(gcc "$src" -o "$pexe"));
    $? >> 8;
};
ok(!$rc, 'compile ok') or diag $out;

($out, $rc) = capture_merged{
    system(qq("$pexe" "$fpriv" "$crypted_hex"));
};
is($out, $plain, 'decrypt ok') or diag $out;

($out, $rc) = capture_merged{
    system(qq("$pexe" "$fpriv" "ecdhes$crypted_hex"));
};
is($out, $plain, 'prefixed decrypt ok') or diag $out;

done_testing();

