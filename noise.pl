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
use CBOR::XS;
use Smart::Comments;

our $CURVE       = 'secp256r1';
our $CIPHER_FUNC = 'AESGCM';
our $HASH_FUNC   = 'SHA256';
our $HASH_LEN    = 32;
our $KEY_LEN     = 32;
our $IV_LEN      = 12;
our $AUTHTAG_LEN = 16;

our %HANDSHAKE_PATTEN = (
  'N' => {
    responder_pre_messages => [qw/s/],
    messages               => [
      [qw/e es/],
    ],
  },
  'K' => {
    initiator_pre_messages => [qw/s/],
    responder_pre_messages => [qw/s/],
    messages               => [
      [qw/e es ss/],
    ],
  },
  'X' => {
    responder_pre_messages => [qw/s/],
    messages               => [
      [qw/e es s ss/],
    ],
  },
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
  'IX' => {
    messages => [
      [qw/e s/],
      [qw/e ee se s es/],
    ],
  },

  'XX' => {
    messages => [
      [qw/e/],
      [qw/e ee s es/],
      [qw/s se/],
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

  if ( length( $handshake_name ) <= $HASH_LEN ) {
    my $x = ( '00' ) x ( $HASH_LEN - length( $handshake_name ) );
    $ss{h} = $handshake_name . pack( "H*", $x );

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

  my $time = time();
  #my ( $ciphertext, $authtag ) = gcm_encrypt_authenticate( 'AES', $key, $iv, $time . $aad, $plaintext );
  
  my $iv_xor = pack("B*", unpack("B*", $iv) ^ unpack("B*", $time));
  my ( $ciphertext, $authtag ) = gcm_encrypt_authenticate( 'AES', $key, $iv_xor, $aad, $plaintext );

  my $cipherinfo = encode_cbor [ $time, $authtag, $ciphertext ];

  ### noise encrypt
  ### key: unpack("H*", $key)
  ### iv: unpack("H*", $iv)
  ### time: unpack("H*", $time)
  ### iv_xor: unpack("H*", $iv_xor)
  ### aad: unpack("H*", $aad)
  ### plaintext: unpack("H*", $plaintext)
  ### ciphertext: unpack("H*", $ciphertext)
  ### authtag: unpack("H*", $authtag)
  ### cipherinfo: unpack("H*", $cipherinfo)

  return $cipherinfo;
} ## end sub aead_encrypt

sub aead_decrypt {
  my ( $key, $iv, $aad, $cipherinfo ) = @_;

  my $d = decode_cbor $cipherinfo;
  my ( $time, $authtag, $ciphertext ) = @$d;

  my $iv_xor = pack("B*", unpack("B*", $iv) ^ unpack("B*", $time));

  my $plaintext = gcm_decrypt_verify( 'AES', $key, $iv_xor, $aad, $ciphertext, $authtag );

  ### noise decrypt
  ### key: unpack("H*", $key)
  ### iv: unpack("H*", $iv)
  ### aad: unpack("H*", $aad)
  ### cipherinfo: unpack("H*", $cipherinfo)
  ### time: unpack("H*", $time)
  ### iv_xor: unpack("H*", $iv_xor)
  ### authtag: unpack("H*", $authtag)
  ### ciphertext: unpack("H*", $ciphertext)
  ### plaintext: unpack("H*", $plaintext)

  return $plaintext;
} ## end sub aead_decrypt

sub encrypt_and_hash {
  my ( $out, $ss, $plaintext ) = @_;

  if ( !$ss->{hasK} ) {
    mix_hash( $ss, $plaintext );

    push @$out, $plaintext;
    return $out;
  }

  my ( $key, $iv ) = noise_derive_key_iv( $ss->{k}, '' );
  my $cipherinfo = aead_encrypt( $key, $iv, $ss->{h}, $plaintext );
  mix_hash( $ss, $cipherinfo );

  push @$out, $cipherinfo;
  return $out;
}

sub decrypt_and_hash {
  my ( $out, $ss, $cipherinfo ) = @_;

  if ( !$ss->{hasK} ) {
    mix_hash( $ss, $cipherinfo );
    push @$out, $cipherinfo;
    return $out;
  }

  my ( $key, $iv ) = noise_derive_key_iv( $ss->{k}, '' );
  my $plaintext = aead_decrypt( $key, $iv, $ss->{h}, $cipherinfo );
  mix_hash( $ss, $cipherinfo );

  push @$out, $plaintext;
  return $out;
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
  ### public compressed: unpack("H*", $public_raw_compressed)

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

  $z =~ s/://g;
  $z = pack( "H*", $z );

  ### ecdh
  ### local_priv: slurp( $local_priv_f )
  ### peer_pub: slurp( $peer_pub_f )
  ### z: unpack("H*", $z)

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
  #s_pub_info_type: raw = compressed point, id = digest of raw, cert, sn = cert serial number
  #s_pub_info_value: s_pub

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

  my $protocol_name = join( "_", "Noise", $hs->{handshake_pattern_name} . $psk_modifier, $hs->{ciphersuite_name} );
  $hs->{ss} = init_symmetric_state( $protocol_name );

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
    ### write message pattern: $m
    if ( $m eq 'e' ) {

      ( $hs->{e_priv}, $hs->{e_pub}, $hs->{e}{pub} ) = generate_key_pair( $CURVE, $hs->{who} . "_e_priv.pem", $hs->{who} . "_e_pub.pem" );

      #( $hs->{e_priv}, $hs->{e_pub}, $hs->{e}{pub} ) =
      #( $hs->{who} . "_e_priv.pem", $hs->{who} . "_e_pub.pem", read_public_key_pem_to_raw( $hs->{who} . "_e_pub.pem" ) );

      push @$out, $hs->{e}{pub};
      mix_hash( $hs->{ss}, $hs->{e}{pub} );
      if ( $hs->{psk} ) {
        mix_key( $hs->{ss}, $hs->{e}{pub} );
      }
    } elsif ( $m eq 's' ) {
      my $s_pub_info_cbor = encode_cbor [ $hs->{s_pub_info_type}, $hs->{s_pub_info_value} ];
      $out = encrypt_and_hash( $out, $hs->{ss}, $s_pub_info_cbor );
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

  $out = encrypt_and_hash( $out, $hs->{ss}, $payload );

  my $out_cbor = encode_cbor $out;
  if ( $hs->{msg_id} >= $m_pattern_len ) {
    my ( $cs1, $cs2 ) = noise_split( $hs->{ss} );
    return ( $out_cbor, $cs1, $cs2 );
  }

  return ( $out_cbor );
} ## end sub write_message

sub read_message {
  my ( $out, $hs, $message_cbor ) = @_;

  if ( $hs->{should_write} ) {
    return;
  }

  my $m_pattern_len = @{ $hs->{message_pattens} };
  if ( $hs->{msg_id} > $m_pattern_len - 1 ) {
    return;
  }

  my $message = decode_cbor $message_cbor;

  my $i = 0;

  for my $m ( @{ $hs->{message_pattens}[ $hs->{msg_id} ] } ) {
    ### read message pattern: $m
    if ( $m eq 'e' or $m eq 's' ) {

      if ( $m eq 'e' ) {

        $hs->{re}{pub} = $message->[$i];
        $hs->{re_pub} = write_public_key_raw_to_pem( $CURVE, $hs->{re}{pub}, $hs->{who} . "_re_pub.pem" );
        mix_hash( $hs->{ss}, $hs->{re}{pub} );
        if ( $hs->{psk} ) {
          mix_key( $hs->{ss}, $hs->{re}{pub} );
        }
      } elsif ( $m eq 's' ) {
        my $temp_m = $message->[$i];

        my $rs_r          = decrypt_and_hash( [], $hs->{ss}, $temp_m );
        my $rs_pub_info_r = decode_cbor $rs_r->[0];
        my ( $rs_pub_info_type, $rs_pub_info_value ) = @$rs_pub_info_r;

        $hs->{rs}{pub} = check_pub_avail( $rs_pub_info_type, $rs_pub_info_value );

        $hs->{rs_pub} = write_public_key_raw_to_pem( $CURVE, $hs->{rs}{pub}, $hs->{who} . "_rs_pub.pem" );
      }

      $i++;
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

  my $temp_m = $message->[$i];
  $out = decrypt_and_hash( $out, $hs->{ss}, $temp_m );

  $hs->{should_write} = 1;
  $hs->{msg_id}++;

  if ( $hs->{msg_id} >= $m_pattern_len ) {
    my ( $cs1, $cs2 ) = noise_split( $hs->{ss} );
    return ( $out, $cs1, $cs2 );
  }
  return ( $out );
} ## end sub read_message

sub check_pub_avail {
  my ( $type, $value ) = @_;
  ### check pub avail: $type, unpack("H*", $value)

  if ( $type eq 'raw' ) {

    #check the value is in the TOFU (trust on first use) record or not
    return $value;                     #pub raw
  }

  if ( $type eq 'id' ) {

    #check the value is in the TOFU (trust on first use) record or not
    #map value to the pub raw
  }

  if ( $type eq 'sn' ) {

    #check the value is in the TOFU (trust on first use) record or not
    #map value to the cert, extract the pub raw from cert
  }

  if ( $type eq 'cert' ) {

    #check the value is in the TOFU (trust on first use) record or not
    #if not, check_cert_avail
    #extract the pub raw from cert
  }
} ## end sub check_pub_avail

noise_test_main();

sub noise_test_main {

  my @test_sub = (
    \&noise_test_one,
    \&noise_test_two,
    \&noise_test_three,
  );

  my @test_psk = ( [ undef, undef ], [ 'test_psk', 0 ], [ 'test_psk', 1 ] );

  # N K X NN NK KK IK IX
  for my $pattern ( qw/N K X NN NK KK IK IX XX/ ) {
    for my $psk_r ( @test_psk ) {
      my ( $psk, $psk_id ) = @$psk_r;
      ### -----------start test --------: $pattern, $psk, $psk_id
      my $a_hs = new_handshake_state(
        { who                    => 'a',
          handshake_pattern_name => $pattern,
          ciphersuite_name       => join( "_", $CURVE, $CIPHER_FUNC, $HASH_FUNC ),
          initiator              => 1,
          prologue               => 'some_info',
          psk                    => $psk,
          psk_id                 => $psk_id,

          s_priv => 'a_s_priv.pem',
          s_pub  => 'a_s_pub.pem',
          rs_pub => 'b_s_pub.pem',

          s_pub_info_type  => 'raw',
          s_pub_info_value => read_public_key_pem_to_raw( 'a_s_pub.pem' ),
        } );

      my $b_hs = new_handshake_state(
        { who                    => 'b',
          handshake_pattern_name => $pattern,
          ciphersuite_name       => join( "_", $CURVE, $CIPHER_FUNC, $HASH_FUNC ),
          initiator              => 0,
          prologue               => 'some_info',
          psk                    => $psk,
          psk_id                 => $psk_id,

          s_priv => 'b_s_priv.pem',
          s_pub  => 'b_s_pub.pem',
          rs_pub => 'a_s_pub.pem',

          s_pub_info_type  => 'raw',
          s_pub_info_value => read_public_key_pem_to_raw( 'b_s_pub.pem' ),
        } );

      my $len = @{ $HANDSHAKE_PATTEN{$pattern}{messages} };
      $test_sub[ $len - 1 ]->( $a_hs, $b_hs );

      ### -----------end test --------: $pattern, $psk, $psk_id
    } ## end for my $psk_r ( @test_psk)
  } ## end for my $pattern ( qw/XX/)
} ## end sub noise_test_main

sub noise_test_one {
  my ( $a_hs, $b_hs ) = @_;

  # a write message to b
  ### init a_hs
  dump( 'a_hs', $a_hs );
  ### a send msg to b
  my $a_msg_src = "init.syn";
  ### $a_msg_src
  my ( $a_msg, $a_c1, $a_c2 ) = write_message( [], $a_hs, $a_msg_src );
  ### a_msg: unpack( "H*", $a_msg )
  dump( 'a_hs', $a_hs, $a_c1, $a_c2 );

  # b read message from a
  ### init b_hs
  dump( 'b_hs', $b_hs );
  ### b recv msg from a
  my ( $b_recv_a_msg_r, $b_c1, $b_c2 ) = read_message( [], $b_hs, $a_msg );
  ### b_recv_a_msg: $b_recv_a_msg_r->[0]
  dump( 'b_hs', $b_hs, $b_c1, $b_c2 );

  # a -> b : plain_a.txt  -> trans_cipherinfo_a
  ### a send comm msg to b
  my ( $a_c1_key, $a_c1_iv ) = noise_derive_key_iv( $a_c1->{k}, '' );
  my $a_trans_cipherinfo_b = aead_encrypt( $a_c1_key, $a_c1_iv, $a_hs->{ss}{h}, slurp( 'plain_a.txt' ) );

  ### b recv comm msg from a
  my ( $b_c1_key, $b_c1_iv ) = noise_derive_key_iv( $b_c1->{k}, '' );
  my $b_recv_plaintext_a = aead_decrypt( $b_c1_key, $b_c1_iv, $b_hs->{ss}{h}, $a_trans_cipherinfo_b );
  ### $b_recv_plaintext_a

  # b -> a : plain_b.txt -> trans_cipherinfo_b
  ### b send comm msg to a
  my ( $b_c2_key, $b_c2_iv ) = noise_derive_key_iv( $b_c2->{k}, '' );
  my $b_trans_cipherinfo_a = aead_encrypt( $b_c2_key, $b_c2_iv, $b_hs->{ss}{h}, slurp( 'plain_b.txt' ) );

  ### a recv comm msg from b
  my ( $a_c2_key, $a_c2_iv ) = noise_derive_key_iv( $a_c2->{k}, '' );
  my $a_recv_plaintext_b = aead_decrypt( $a_c2_key, $a_c2_iv, $a_hs->{ss}{h}, $b_trans_cipherinfo_a );
  ### $a_recv_plaintext_b

} ## end sub noise_test_one

sub noise_test_two {
  my ( $a_hs, $b_hs ) = @_;

  ### a write message to b
  ### init a_hs
  dump( $a_hs );
  ### a send msg to b
  my $a_msg_src = "init.syn";
  my ( $a_msg ) = write_message( [], $a_hs, $a_msg_src );
  dump( 'a_msg', $a_msg );
  dump( 'a_hs',  $a_hs );

  ### b read message from a
  ### init b_hs
  dump( $b_hs );
  ### b recv msg from a
  my ( $b_recv_a_msg_r ) = read_message( [], $b_hs, $a_msg );
  dump( 'b_recv_a_msg', $b_recv_a_msg_r->[0] );
  dump( 'b_hs',         $b_hs );

  ### b write_message to a
  ### b send msg to a
  my $b_msg_src = "resp.ack";
  my ( $b_msg, $b_c1, $b_c2 ) = write_message( [], $b_hs, $b_msg_src );
  ### b_msg: unpack("H*", $b_msg)
  dump( $b_hs, $b_c1, $b_c2 );

  ### a read_message from b
  ### a recv msg from b
  my ( $a_recv_b_msg_r, $a_c1, $a_c2 ) = read_message( [], $a_hs, $b_msg );
  dump( 'a_recv_b_msg', $a_recv_b_msg_r->[0] );
  dump( $a_hs, $a_c1, $a_c2 );

  # a -> b : plain_a.txt  -> trans_cipherinfo_a
  ### a send comm msg to b
  my ( $a_c1_key, $a_c1_iv ) = noise_derive_key_iv( $a_c1->{k}, '' );
  my $a_trans_cipherinfo_b = aead_encrypt( $a_c1_key, $a_c1_iv, $a_hs->{ss}{h}, slurp( 'plain_a.txt' ) );
  ### b recv comm msg from a
  my ( $b_c1_key, $b_c1_iv ) = noise_derive_key_iv( $b_c1->{k}, '' );
  my $b_recv_plaintext_a = aead_decrypt( $b_c1_key, $b_c1_iv, $b_hs->{ss}{h}, $a_trans_cipherinfo_b );
  ### $b_recv_plaintext_a

  ### b to a , plain_b.txt to trans_cipherinfo_b
  ### b send comm msg to a
  my ( $b_c2_key, $b_c2_iv ) = noise_derive_key_iv( $b_c2->{k}, '' );
  my $b_trans_cipherinfo_a = aead_encrypt( $b_c2_key, $b_c2_iv, $b_hs->{ss}{h}, slurp( 'plain_b.txt' ) );
  ### a recv comm msg from b
  my ( $a_c2_key, $a_c2_iv ) = noise_derive_key_iv( $a_c2->{k}, '' );
  my $a_recv_plaintext_b = aead_decrypt( $a_c2_key, $a_c2_iv, $a_hs->{ss}{h}, $b_trans_cipherinfo_a );
  ### $a_recv_plaintext_b
} ## end sub noise_test_two

sub noise_test_three {
  my ( $a_hs, $b_hs ) = @_;

  ### a write message to b
  ### init a_hs
  dump( $a_hs );
  ### a send msg to b
  my $a_msg_src = "init.syn";
  my ( $a_msg ) = write_message( [], $a_hs, $a_msg_src );
  dump( 'a_msg', $a_msg );
  dump( 'a_hs',  $a_hs );

  ### b read message from a
  ### init b_hs
  dump( $b_hs );
  ### b recv msg from a
  my ( $b_recv_a_msg_r ) = read_message( [], $b_hs, $a_msg );
  dump( 'b_recv_a_msg', $b_recv_a_msg_r->[0] );
  dump( 'b_hs',         $b_hs );

  ### b write_message to a
  ### b send msg to a
  my $b_msg_src = "resp.ack";
  my ( $b_msg ) = write_message( [], $b_hs, $b_msg_src );
  ### b_msg: unpack("H*", $b_msg)
  dump( $b_hs );

  ### a read_message from b
  ### a recv msg from b
  my ( $a_recv_b_msg_r ) = read_message( [], $a_hs, $b_msg );
  dump( 'a_recv_b_msg', $a_recv_b_msg_r->[0] );
  dump( $a_hs );

  # a write message to b
  ### a send msg to b
  my $a_msg2_src = "init.ack";
  ### $a_msg2_src
  my ( $a_msg2, $a_c1, $a_c2 ) = write_message( [], $a_hs, $a_msg2_src );
  ### a_msg2: unpack( "H*", $a_msg2 )
  dump( 'a_hs', $a_hs, $a_c1, $a_c2 );

  # b read message from a
  ### b recv msg from a
  my ( $b_recv_a_msg2_r, $b_c1, $b_c2 ) = read_message( [], $b_hs, $a_msg2 );
  ### b_recv_a_msg2: $b_recv_a_msg2_r->[0]
  dump( 'b_hs', $b_hs, $b_c1, $b_c2 );

  # a -> b : plain_a.txt  -> trans_cipherinfo_a
  ### a send comm msg to b
  my ( $a_c1_key, $a_c1_iv ) = noise_derive_key_iv( $a_c1->{k}, '' );
  my $a_trans_cipherinfo_b = aead_encrypt( $a_c1_key, $a_c1_iv, $a_hs->{ss}{h}, slurp( 'plain_a.txt' ) );
  ### b recv comm msg from a
  my ( $b_c1_key, $b_c1_iv ) = noise_derive_key_iv( $b_c1->{k}, '' );
  my $b_recv_plaintext_a = aead_decrypt( $b_c1_key, $b_c1_iv, $b_hs->{ss}{h}, $a_trans_cipherinfo_b );
  ### $b_recv_plaintext_a

  ### b to a , plain_b.txt to trans_cipherinfo_b
  ### b send comm msg to a
  my ( $b_c2_key, $b_c2_iv ) = noise_derive_key_iv( $b_c2->{k}, '' );
  my $b_trans_cipherinfo_a = aead_encrypt( $b_c2_key, $b_c2_iv, $b_hs->{ss}{h}, slurp( 'plain_b.txt' ) );
  ### a recv comm msg from b
  my ( $a_c2_key, $a_c2_iv ) = noise_derive_key_iv( $a_c2->{k}, '' );
  my $a_recv_plaintext_b = aead_decrypt( $a_c2_key, $a_c2_iv, $a_hs->{ss}{h}, $b_trans_cipherinfo_a );
  ### $a_recv_plaintext_b
} ## end sub noise_test_three
