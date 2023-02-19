# Google Authenticator QR code export dumper / decoder

There are a few of these already, but all seem to be in NodeJS or Python and have a kitchen
sink full of dependencies. This one is a single stand alone C program, that uses the standard
`base64` and `base32` utilities and a built-in minimal protobuf decoder.

Phil.
