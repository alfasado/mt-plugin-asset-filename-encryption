package AssetFilenameEncryption::Plugin;
use strict;

use Encode;
use Crypt::RC4;
use File::Basename;

sub _asset_upload_path {
    my ( $cb, $app, $fmgr, $path_info ) = @_;
    return if $app->param( 'overwrite_yes' );
    my $suffixes = MT->config( 'AssetFilenameEncryptionSuffix' );
    my @check = split( /,/, $suffixes );
    my $basename = $path_info->{ basename };
    my $original = $basename;
    my $regex_suffix = qw(\.[^\.]+$);
    my @parse = fileparse( $basename, $regex_suffix );
    my $file_base = $parse[ 0 ];
    my $suffix = lc( $parse[ 2 ] );
    $suffix =~ s/^\.//;
    return if (! grep( /^$suffix$/, @check ) );
    my $passphrase = MT->config( 'AssetFilenameEncryptionPassPhrase' );
    $file_base = __encrypt( $passphrase, $file_base );
    $file_base .= '.' . $suffix;
    $path_info->{ basename } = $file_base;
}

sub _upload_file {
    my ( $cb, %args ) = @_;
    my $app = MT->instance;
    return if ( ref $app ) !~ /^MT::App::/;
    my $asset = $args{ asset };
    my $basename = $asset->file_name;
    my $suffixes = MT->config( 'AssetFilenameEncryptionSuffix' );
    my @check = split( /,/, $suffixes );
    my $regex_suffix = qw(\.[^\.]+$);
    my @parse = fileparse( $basename, $regex_suffix );
    my $file_base = $parse[ 0 ];
    my $suffix = lc( $parse[ 2 ] );
    $suffix =~ s/^\.//;
    return if (! grep( /^$suffix$/, @check ) );
    my $passphrase = MT->config( 'AssetFilenameEncryptionPassPhrase' );
    my $original = __decrypt( $passphrase, $file_base ) . '.' . $suffix;
    if ( $asset->label ne $original ) {
        $asset->label( $original );
        $asset->save or die $asset->errstr;
    }
}

sub __encrypt {
  my ( $passphrase, $plaintext ) = @_;
  $plaintext = MT::I18N::utf8_off( $plaintext );
  my $encrypted = RC4( $passphrase, $plaintext );
  $encrypted =~ s/(.)/unpack('H2', $1)/eg;
  return $encrypted;
}

sub __decrypt {
  my ( $passphrase, $encrypted ) = @_;
  $encrypted = MT::I18N::utf8_off( $encrypted );
  $encrypted =~ s/([0-9A-Fa-f]{2})/pack('H2', $1)/eg;
  my $decrypted = RC4( $passphrase, $encrypted );
  Encode::_utf8_on( $decrypted );
  return $decrypted;
}

1;