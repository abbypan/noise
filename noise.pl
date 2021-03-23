#!/usr/bin/perl

use strict;
use warnings;

use Crypt::KeyDerivation ':all';
use Digest::SHA qw/hmac_sha256 sha256/;
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::PK::ECC;
use Data::Dump qw/dump/;
use File::Slurp qw/slurp write_file/;
use Storable qw(dclone);
use Crypt::OpenSSL::Base::Func qw/ecdh/;
use POSIX qw/strftime/;

our $CURVE       = 'secp256r1';
our $CIPHER_FUNC = 'AESGCM';
our $HASH_FUNC   = 'SHA256';
our $HASH_LEN    = 32;
our $KEY_LEN     = 32;
our $IV_LEN      = 12;
our $AUTHTAG_LEN = 16;
our $DH_LEN      = 32;
our $TIME_LEN = 10;

our %HANDSHAKE_PATTEN = (
  'NN' => {
    messages => [
      [qw/e/],
      [qw/e ee/],
    ],
  },
  'NK' => {
    responder_pre_messages => [qw/s/],

    messages => [
      [qw/e es/],
      [qw/e ee/],
    ],
  },
  'KK' => {
    initiator_pre_messages => [qw/s/],
    responder_pre_messages => [qw/s/],
    messages               => [
      [qw/e es ss/],
      [qw/e ee se/],
    ],
  },
  'IK' => {
    responder_pre_messages => [qw/s/],
    messages               => [
      [qw/e es s ss/],
      [qw/e ee se/],
    ],
  },
);

sub noise_hkdf {
  my ( $chaining_key, $input_key_material, $num_outputs ) = @_;

  my $temp_key = hmac_sha256( $input_key_material, $chaining_key );

  my $out1 = hmac_sha256( pack( "H*", "01" ), $temp_key );
  return $out1 if ( $num_outputs == 1 );

  my $out2 = hmac_sha256( $out1 || pack( "H*", "02" ), $temp_key );
  return ( $out1, $out2 ) if ( $num_outputs == 2 );

  my $out3 = hmac_sha256( $out2 || pack( "H*", "03" ), $temp_key );
  return ( $out1, $out2, $out3 ) if ( $num_outputs == 3 );

}

sub init_symmetric_state {
  my ( $handshake_name ) = @_;
  my %ss;

  #print length($handshake_name),"\n";
  if ( length( $handshake_name ) <= $HASH_LEN ) {
    my $x = ( '00' ) x ( $HASH_LEN - length( $handshake_name ) );
    $ss{h} = $handshake_name . pack( "H*", $x );

    #print unpack("H*", $ss{h}), "\n";
  } else {
    $ss{h} = sha256( $handshake_name );
  }
  $ss{ck} = $ss{h};
  return \%ss;
}

sub mix_key {
  my ( $ss, $dh ) = @_;
  $ss->{hasK} = 1;
  ( $ss->{ck}, $ss->{k} ) = noise_hkdf( $ss->{ck}, $dh, 2 );
  return $ss;
}

sub mix_hash {
  my ( $ss, $data ) = @_;
  $ss->{h} = sha256( $ss->{h} . $data );
  return $ss;
}

sub init_key {
  my ( $ss, $k ) = @_;
  $ss->{k}    = $k;
  $ss->{hasK} = 1;
  return $ss;
}

sub mix_keyandhash {
  my ( $ss, $data ) = @_;
  my $temp_h;
  my $temp_k;
  ( $ss->{ck}, $temp_h, $temp_k ) = noise_hkdf( $ss->{ck}, $data, 3 );
  mix_hash( $ss, $temp_h );
  if ( length( $temp_k ) > $HASH_LEN ) {
    $temp_k = substr( $temp_k, 0, $HASH_LEN );
  }
  init_key( $ss, $temp_k );
  return $ss;
}

sub noise_derive_key_iv {
  my ( $k, $salt ) = @_;

  #$derived_key3 = hkdf($keying_material, $salt, $hash_name, $len, $info);
  my $key = hkdf( $k, $salt, $HASH_FUNC, $KEY_LEN, "Noise Key" );
  my $iv  = hkdf( $k, $salt, $HASH_FUNC, $IV_LEN,  "Noise IV" );
  return ( $key, $iv );
}

sub aead_encrypt {
  my ( $key, $iv, $aad, $plaintext ) = @_;

  my $time = time();  # $TIME_LEN
  my ( $ciphertext, $authtag ) = gcm_encrypt_authenticate( 'AES', $key, $iv, $time.$aad, $plaintext );
  my $cipherinfo = $time.$authtag.$ciphertext;

  print "\nnoise encrypt:\n";
  print "key:\n",        unpack( "H*", $key ),        "\n";
  print "iv:\n",         unpack( "H*", $iv ),         "\n";
  print "time:\n",        unpack( "H*", $time ),        "\n";
  print "aad:\n",        unpack( "H*", $aad ),        "\n";
  print "plaintext:\n",  unpack( "H*", $plaintext ),  "\n\n";
  print "ciphertext:\n", unpack( "H*", $ciphertext ), "\n";
  print "authtag:\n",    unpack( "H*", $authtag ),    "\n";
  print "cipherinfo:\n", unpack( "H*", $cipherinfo ), "\n";

  return $cipherinfo;
}

sub aead_decrypt {
  my ( $key, $iv, $aad, $cipherinfo ) = @_;

  my $time    = substr $cipherinfo, 0, $TIME_LEN;
  my $authtag    = substr $cipherinfo, $TIME_LEN, $AUTHTAG_LEN;
  my $ciphertext = substr $cipherinfo, $TIME_LEN+$AUTHTAG_LEN, length( $cipherinfo ) - $AUTHTAG_LEN;
  my $plaintext  = gcm_decrypt_verify( 'AES', $key, $iv, $time.$aad, $ciphertext, $authtag );

  print "\nnoise decrypt:\n";
  print "key:\n",        unpack( "H*", $key ),        "\n";
  print "iv:\n",         unpack( "H*", $iv ),         "\n";
  print "aad:\n",        unpack( "H*", $aad ),        "\n";
  print "cipherinfo:\n", unpack( "H*", $cipherinfo ), "\n";
  print "time:\n",        unpack( "H*", $time ),        "\n";
  print "authtag:\n",    unpack( "H*", $authtag ),    "\n";
  print "ciphertext:\n", unpack( "H*", $ciphertext ), "\n\n";
  print "plaintext:\n",  unpack( "H*", $plaintext ),  "\n";

  return $plaintext;
} ## end sub aead_decrypt

sub encrypt_and_hash {
  my ( $out, $ss, $plaintext ) = @_;

  if ( !$ss->{hasK} ) {
    mix_hash( $ss, $plaintext );
    return $out . $plaintext;
  }

  my ( $key, $iv ) = noise_derive_key_iv( $ss->{k}, '' );
  my $cipherinfo = aead_encrypt( $key, $iv, $ss->{h}, $plaintext );
  mix_hash( $ss, $cipherinfo );
  return $out . $cipherinfo;
}

sub decrypt_and_hash {
  my ( $out, $ss, $cipherinfo ) = @_;

  if ( !$ss->{hasK} ) {
    mix_hash( $ss, $cipherinfo );
    return $out . $cipherinfo;
  }

  my ( $key, $iv ) = noise_derive_key_iv( $ss->{k}, '' );
  my $plaintext = aead_decrypt( $key, $iv, $ss->{h}, $cipherinfo );
  mix_hash( $ss, $cipherinfo );
  return $out . $plaintext;
}

sub noise_split {
  my ( $ss ) = @_;
  my ( $temp_k1, $temp_k2 ) = noise_hkdf( $ss->{k}, '', 2 );
  if ( length( $temp_k1 ) > $HASH_LEN ) {
    $temp_k1 = substr( $temp_k1, 0, $HASH_LEN );
    $temp_k2 = substr( $temp_k2, 0, $HASH_LEN );
  }

  my $c1_ss = {};
  init_key( $c1_ss, $temp_k1 );
  my $c2_ss = {};
  init_key( $c2_ss, $temp_k2 );

  return ( $c1_ss, $c2_ss );
}

sub generate_key_pair {
  my ( $curve, $priv_f, $pub_f ) = @_;

  #system(qq[openssl ecparam -genkey -name prime256v1 -out $priv_f]);
  #system(qq[openssl ec -in $priv_f -pubout -out $pub_f]);

  my $pk = Crypt::PK::ECC->new();
  $pk->generate_key( $curve );

  my $private_pem = $pk->export_key_pem( 'private_short' );
  write_file( $priv_f, $private_pem );

  my $public_pem = $pk->export_key_pem( 'public_short' );
  write_file( $pub_f, $public_pem );

  #$pk->import_key($pub_f);
  my $public_raw_compressed = $pk->export_key_raw( 'public_compressed' );
  dump( "public compressed", $public_raw_compressed );

  return ( $priv_f, $pub_f, $public_raw_compressed );
} ## end sub generate_key_pair

sub read_public_key_pem_to_raw {
  my ( $pub_f ) = @_;
  my $pk = Crypt::PK::ECC->new();
  $pk->import_key( $pub_f );
  my $public_raw_compressed = $pk->export_key_raw( 'public_compressed' );
  return $public_raw_compressed;
}

sub write_public_key_raw_to_pem {
  my ( $curve, $public_raw_compressed, $pub_f ) = @_;
  my $pk = Crypt::PK::ECC->new();
  $pk->import_key_raw( $public_raw_compressed, $curve );
  my $public_pem = $pk->export_key_pem( 'public_short' );
  write_file( $pub_f, $public_pem );
  return $pub_f;
}

sub noise_ecdh {
  my ( $local_priv_f, $peer_pub_f ) = @_;
  my $z = ecdh( $local_priv_f, $peer_pub_f );

  print "ecdh: $local_priv_f, $peer_pub_f, $z\n";
  print "local_priv:\n", slurp( $local_priv_f ), "\n";
  print "peer_pub:\n",   slurp( $peer_pub_f ),   "\n";
  print "z:\n",          $z, "\n";
  $z =~ s/://g;
  $z = pack( "H*", $z );
  return $z;
}

sub new_handshake_state {
  my ( $conf ) = @_;

  #handshake_pattern_name => NN, ...
  #ciphersuite_name => secp256r1_AESGCM_SHA256
  #initiator
  #prologue => some_info
  #psk
  #psk_id
  #s_priv: local_static_priv
  #s_pub: local_static_pub
  #e_priv: local_ephemeral_priv
  #e_pub: local_ephemeral_pub
  #rs_pub: peer_static_pub
  #re_pub: peer_ephemeral_pub

  my $hs = dclone( $conf );
  $hs->{message_pattens} = dclone( $HANDSHAKE_PATTEN{ $hs->{handshake_pattern_name} }{messages} );
  $hs->{should_write}    = $hs->{initiator};
  $hs->{msg_id}          = 0;

  #psk
  my $psk_modifier = '';
  if ( $hs->{psk} ) {
    my $psk_id = $hs->{psk_id};
    $psk_modifier = "psk$psk_id";
    if ( $psk_id == 0 ) {
      unshift @{ $hs->{message_pattens}[0] }, 'psk';
    } else {
      push @{ $hs->{message_pattens}[ $psk_id - 1 ] }, 'psk';
    }
  }

  $hs->{ss} = init_symmetric_state( "Noise_" . $hs->{handshake_pattern_name} . $psk_modifier . "_" . $hs->{ciphersuite_name} );

  mix_hash( $hs->{ss}, $hs->{prologue} );

  for my $m ( @{ $HANDSHAKE_PATTEN{ $hs->{handshake_pattern_name} }{initiator_pre_messages} } ) {
    if ( $hs->{initiator} and ( $m eq 's' ) ) {
      mix_hash( $hs->{ss}, read_public_key_pem_to_raw( $hs->{s_pub} ) );
    } elsif ( $hs->{initiator} and ( $m eq 'e' ) ) {
      mix_hash( $hs->{ss}, read_public_key_pem_to_raw( $hs->{e_pub} ) );
    } elsif ( ( !$hs->{initiator} ) and ( $m eq 's' ) ) {
      mix_hash( $hs->{ss}, read_public_key_pem_to_raw( $hs->{rs_pub} ) );
    } elsif ( ( !$hs->{initiator} ) and ( $m eq 'e' ) ) {
      mix_hash( $hs->{ss}, read_public_key_pem_to_raw( $hs->{re_pub} ) );
    }
  }

  for my $m ( @{ $HANDSHAKE_PATTEN{ $hs->{handshake_pattern_name} }{responder_pre_messages} } ) {
    if ( $hs->{initiator} and ( $m eq 's' ) ) {
      mix_hash( $hs->{ss}, read_public_key_pem_to_raw( $hs->{rs_pub} ) );
    } elsif ( $hs->{initiator} and ( $m eq 'e' ) ) {
      mix_hash( $hs->{ss}, read_public_key_pem_to_raw( $hs->{re_pub} ) );
    } elsif ( ( !$hs->{initiator} ) and ( $m eq 's' ) ) {
      mix_hash( $hs->{ss}, read_public_key_pem_to_raw( $hs->{s_pub} ) );
    } elsif ( ( !$hs->{initiator} ) and ( $m eq 'e' ) ) {
      mix_hash( $hs->{ss}, read_public_key_pem_to_raw( $hs->{e_pub} ) );
    }
  }

  return $hs;
} ## end sub new_handshake_state

sub write_message {
  my ( $out, $hs, $payload ) = @_;

  if ( !$hs->{should_write} ) {
    return;
  }

  my $m_pattern_len = @{ $hs->{message_pattens} };
  if ( $hs->{msg_id} > $m_pattern_len - 1 ) {
    return;
  }

  for my $m ( @{ $hs->{message_pattens}[ $hs->{msg_id} ] } ) {
    print "write message pattern: $m\n";
    if ( $m eq 'e' ) {

      ( $hs->{e_priv}, $hs->{e_pub}, $hs->{e}{pub} ) = generate_key_pair( $CURVE, $hs->{who} . "_e_priv.pem", $hs->{who} . "_e_pub.pem" );

      #( $hs->{e_priv}, $hs->{e_pub}, $hs->{e}{pub} ) =
        #( $hs->{who} . "_e_priv.pem", $hs->{who} . "_e_pub.pem", read_public_key_pem_to_raw( $hs->{who} . "_e_pub.pem" ) );

      $out .= $hs->{e}{pub};
      mix_hash( $hs->{ss}, $hs->{e}{pub} );
      if ( $hs->{psk} ) {
        mix_key( $hs->{ss}, $hs->{e}{pub} );
      }
    } elsif ( $m eq 's' ) {
      $out = encrypt_and_hash( $out, $hs->{ss}, read_public_key_pem_to_raw( $hs->{s_pub} ) );
    } elsif ( $m eq 'ee' ) {
      mix_key( $hs->{ss}, noise_ecdh( $hs->{e_priv}, $hs->{re_pub} ) );
    } elsif ( $m eq 'es' ) {
      if ( $hs->{initiator} ) {
        mix_key( $hs->{ss}, noise_ecdh( $hs->{e_priv}, $hs->{rs_pub} ) );
      } else {
        mix_key( $hs->{ss}, noise_ecdh( $hs->{s_priv}, $hs->{re_pub} ) );
      }
    } elsif ( $m eq 'se' ) {
      if ( $hs->{initiator} ) {
        mix_key( $hs->{ss}, noise_ecdh( $hs->{s_priv}, $hs->{re_pub} ) );
      } else {
        mix_key( $hs->{ss}, noise_ecdh( $hs->{e_priv}, $hs->{rs_pub} ) );
      }
    } elsif ( $m eq 'ss' ) {
      mix_key( $hs->{ss}, noise_ecdh( $hs->{s_priv}, $hs->{rs_pub} ) );
    } elsif ( $m eq 'psk' ) {
      mix_keyandhash( $hs->{ss}, $hs->{psk} );
    }

  } ## end for my $m ( @{ $hs->{message_pattens...}})

  $hs->{should_write} = 0;
  $hs->{msg_id}++;

  dump( 'encrypt_and_hash', $hs->{ss} );
  $out = encrypt_and_hash( $out, $hs->{ss}, $payload );

  if ( $hs->{msg_id} >= $m_pattern_len ) {
    my ( $cs1, $cs2 ) = noise_split( $hs->{ss} );
    return ( $out, $cs1, $cs2 );
  }

  return ( $out );
} ## end sub write_message

sub read_message {
  my ( $out, $hs, $message ) = @_;

  if ( $hs->{should_write} ) {
    return;
  }

  my $m_pattern_len = @{ $hs->{message_pattens} };
  if ( $hs->{msg_id} > $m_pattern_len - 1 ) {
    return;
  }

  my $pub_raw_len = $DH_LEN + 1;       #ec compressed point
  if ( $CURVE eq '25519' ) {
    $pub_raw_len = $DH_LEN;
  }

  my $i = 0;
  my $expected;

  for my $m ( @{ $hs->{message_pattens}[ $hs->{msg_id} ] } ) {
    print "read message pattern: $m\n";
    if ( $m eq 'e' or $m eq 's' ) {
      $expected = $pub_raw_len;
      if ( $m eq 's' and $hs->{ss}{hasK} ) {
        $expected += $TIME_LEN+$AUTHTAG_LEN;
      }

      if ( $m eq 'e' ) {
        $hs->{re}{pub} = substr $message, $i, $expected;
        $hs->{re_pub}  = write_public_key_raw_to_pem( $CURVE, $hs->{re}{pub}, $hs->{who} . "_re_pub.pem" );
        mix_hash( $hs->{ss}, $hs->{re}{pub} );
        if ( $hs->{psk} ) {
          mix_key( $hs->{ss}, $hs->{re}{pub} );
        }
      } elsif ( $m eq 's' ) {
        my $temp_m = substr $message, $i, $expected;
        $hs->{rs}{pub} = decrypt_and_hash( '', $hs->{ss}, $temp_m );
        $hs->{rs_pub} = write_public_key_raw_to_pem( $CURVE, $hs->{rs}{pub}, $hs->{who} . "_rs_pub.pem" );
      }
      $i += $expected;
    } elsif ( $m eq 'ee' ) {
      mix_key( $hs->{ss}, noise_ecdh( $hs->{e_priv}, $hs->{re_pub} ) );
    } elsif ( $m eq 'es' ) {
      if ( $hs->{initiator} ) {
        mix_key( $hs->{ss}, noise_ecdh( $hs->{e_priv}, $hs->{rs_pub} ) );
      } else {
        mix_key( $hs->{ss}, noise_ecdh( $hs->{s_priv}, $hs->{re_pub} ) );
      }
    } elsif ( $m eq 'se' ) {
      if ( $hs->{initiator} ) {
        mix_key( $hs->{ss}, noise_ecdh( $hs->{s_priv}, $hs->{re_pub} ) );
      } else {
        mix_key( $hs->{ss}, noise_ecdh( $hs->{e_priv}, $hs->{rs_pub} ) );
      }
    } elsif ( $m eq 'ss' ) {
      mix_key( $hs->{ss}, noise_ecdh( $hs->{s_priv}, $hs->{rs_pub} ) );
    } elsif ( $m eq 'psk' ) {
      mix_keyandhash( $hs->{ss}, $hs->{psk} );
    }
  } ## end for my $m ( @{ $hs->{message_pattens...}})

  my $temp_m = substr $message, $i;
  $out = decrypt_and_hash( $out, $hs->{ss}, $temp_m );

  $hs->{should_write} = 1;
  $hs->{msg_id}++;

  if ( $hs->{msg_id} >= $m_pattern_len ) {
    my ( $cs1, $cs2 ) = noise_split( $hs->{ss} );
    return ( $out, $cs1, $cs2 );
  }
  return ( $out );
} ## end sub read_message

test_nn();
test_nk();
test_kk();
test_ik();

sub test_ik {
  print "test ik\n";
  my $a_hs = new_handshake_state(
    { who                    => 'a',
      handshake_pattern_name => 'IK',
      ciphersuite_name       => 'secp256r1_AESGCM_SHA256',
      initiator              => 1,
      prologue               => 'some_info',
      psk                    => undef,
      psk_id                 => undef,

      s_priv => 'a_s_priv.pem',
      s_pub  => 'a_s_pub.pem',
      rs_pub => 'b_s_pub.pem',

    } );

  my $b_hs = new_handshake_state(
    { who                    => 'b',
      handshake_pattern_name => 'IK',
      ciphersuite_name       => 'secp256r1_AESGCM_SHA256',
      initiator              => 0,
      prologue               => 'some_info',
      psk                    => undef,
      psk_id                 => undef,

      s_priv => 'b_s_priv.pem',
      s_pub  => 'b_s_pub.pem',

    } );

  test_noise( $a_hs, $b_hs );
} ## end sub test_ik

sub test_kk {
  print "test kk\n";
  my $a_hs = new_handshake_state(
    { who                    => 'a',
      handshake_pattern_name => 'KK',
      ciphersuite_name       => 'secp256r1_AESGCM_SHA256',
      initiator              => 1,
      prologue               => 'some_info',
      psk                    => undef,
      psk_id                 => undef,

      s_priv => 'a_s_priv.pem',
      s_pub  => 'a_s_pub.pem',
      rs_pub => 'b_s_pub.pem',

    } );

  my $b_hs = new_handshake_state(
    { who                    => 'b',
      handshake_pattern_name => 'KK',
      ciphersuite_name       => 'secp256r1_AESGCM_SHA256',
      initiator              => 0,
      prologue               => 'some_info',
      psk                    => undef,
      psk_id                 => undef,

      s_priv => 'b_s_priv.pem',
      s_pub  => 'b_s_pub.pem',
      rs_pub => 'a_s_pub.pem',

    } );

  test_noise( $a_hs, $b_hs );
} ## end sub test_kk

sub test_nk {
  print "test nk\n";
  my $a_hs = new_handshake_state(
    { who                    => 'a',
      handshake_pattern_name => 'NK',
      ciphersuite_name       => 'secp256r1_AESGCM_SHA256',
      initiator              => 1,
      prologue               => 'some_info',
      psk                    => undef,
      psk_id                 => undef,

      rs_pub => 'b_s_pub.pem',

    } );

  my $b_hs = new_handshake_state(
    { who                    => 'b',
      handshake_pattern_name => 'NK',
      ciphersuite_name       => 'secp256r1_AESGCM_SHA256',
      initiator              => 0,
      prologue               => 'some_info',
      psk                    => undef,
      psk_id                 => undef,

      s_priv => 'b_s_priv.pem',
      s_pub  => 'b_s_pub.pem',

    } );

  test_noise( $a_hs, $b_hs );
} ## end sub test_nk

sub test_nn {
  print "test nn\n";
  my $a_hs = new_handshake_state(
    { who                    => 'a',
      handshake_pattern_name => 'NN',
      ciphersuite_name       => 'secp256r1_AESGCM_SHA256',
      initiator              => 1,
      prologue               => 'some_info',
      psk                    => undef,
      psk_id                 => undef,
    } );

  my $b_hs = new_handshake_state(
    { who                    => 'b',
      handshake_pattern_name => 'NN',
      ciphersuite_name       => 'secp256r1_AESGCM_SHA256',
      initiator              => 0,
      prologue               => 'some_info',
      psk                    => undef,
      psk_id                 => undef,
    } );

  test_noise( $a_hs, $b_hs );
} ## end sub test_nn

sub test_noise {
  my ( $a_hs, $b_hs ) = @_;

  # -> e
  # a
  print "\ninit a_hs:\n";
  dump( $a_hs );
  print "a send msg to b:\n";
  my $a_msg_src = strftime("%Y%m%d%H%M%S.init", localtime);
  my ( $a_msg ) = write_message( '', $a_hs, $a_msg_src );
  dump( 'a_msg', $a_msg );
  print "a_msg:\n", unpack( "H*", $a_msg ), "\n";
  dump( 'a_hs', $a_hs );
  print "\n-----------\n\n";

  # b
  print "\ninit b_hs:\n";
  dump( $b_hs );
  print "b recv msg from a:\n";
  my ( $b_recv_a_msg ) = read_message( '', $b_hs, $a_msg );
  dump( 'b_recv_a_msg', $b_recv_a_msg );
  print "b_recv_a_msg:\n", unpack( "H*", $b_recv_a_msg ), "\n";
  dump( 'b_hs', $b_hs );
  print "\n-----------\n\n";

  # <- e, ee
  # b
  print "\nb send msg to a:\n";
  my $b_msg_src = strftime("%Y%m%d%H%M%S.resp", localtime);
  my ( $b_msg, $b_c1, $b_c2 ) = write_message( '', $b_hs, $b_msg_src );
  dump( 'b_msg', $b_msg );
  print "b_msg:\n", unpack( "H*", $b_msg ), "\n";
  dump( $b_hs, $b_c1, $b_c2 );
  print "\n-----------\n\n";

  # a
  print "\na recv msg from b:\n";
  my ( $a_recv_b_msg, $a_c1, $a_c2 ) = read_message( '', $a_hs, $b_msg );
  dump( 'a_recv_b_msg', $a_recv_b_msg );
  print "a_recv_b_msg:\n", unpack( "H*", $a_recv_b_msg ), "\n";
  dump( $a_hs, $a_c1, $a_c2 );
  print "\n-----------\n\n";

  # a -> b : plain_a.txt  -> trans_cipherinfo_a
  print "\na send comm msg to b:\n";
  my ( $a_c1_key, $a_c1_iv ) = noise_derive_key_iv( $a_c1->{k}, $a_msg_src . $a_recv_b_msg );
  my $a_trans_cipherinfo_b = aead_encrypt( $a_c1_key, $a_c1_iv, $a_hs->{ss}{h}, slurp( 'plain_a.txt' ) );
  print "\nb recv comm msg from a:\n";
  my ( $b_c1_key, $b_c1_iv ) = noise_derive_key_iv( $b_c1->{k}, $b_recv_a_msg . $b_msg_src );
  my $b_recv_plaintext_a = aead_decrypt( $b_c1_key, $b_c1_iv, $b_hs->{ss}{h}, $a_trans_cipherinfo_b );
  print $b_recv_plaintext_a, "\n";
  print "\n-----------\n\n";

  # b -> a : plain_b.txt  -> trans_cipherinfo_b
  print "\nb send comm msg to a:\n";
  my ( $b_c2_key, $b_c2_iv ) = noise_derive_key_iv( $b_c2->{k}, $b_recv_a_msg . $b_msg_src );
  my $b_trans_cipherinfo_a = aead_encrypt( $b_c2_key, $b_c2_iv, $b_hs->{ss}{h}, slurp( 'plain_b.txt' ) );
  print "\na recv comm msg from b:\n";
  my ( $a_c2_key, $a_c2_iv ) = noise_derive_key_iv( $a_c2->{k}, $a_msg_src . $a_recv_b_msg );
  my $a_recv_plaintext_b = aead_decrypt( $a_c2_key, $a_c2_iv, $a_hs->{ss}{h}, $b_trans_cipherinfo_a );
  print $a_recv_plaintext_b, "\n";
  print "\n-----------\n\n";
} ## end sub test_noise
