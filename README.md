# noise
noise protocol

see also:
- https://noiseprotocol.org/noise.pdf
- https://github.com/flynn/noise

remove cipher state: nonce n

remove symmetric state: prevCK, prevH

add hkdf for aead, derive key, iv

add time() for aead aad
