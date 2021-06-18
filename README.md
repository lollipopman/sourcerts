# SourCerts

A proof of concept to ascertain the feasibility of using eBPF to monitor
TLS certificate expirations. This test uses a uretprobe on OpenSSL's
libssl to introspect the certificate of any application using libssl and
making a call to `SSL_get_peer_certificate`.

## Build

    make build

## Run

    sudo ./sourcerts
    ./tests/https_get.rb

# Example Probe Data

    Pid: 1322867
        notBefore:  2021-05-24 03:58:34 +0000 UTC
        notAfter:   2021-08-16 03:58:33 +0000 UTC
        Subject:    US, California, Mountain View, Google LLC, www.google.com
        Issuer:     US, Google Trust Services, GTS CA 1O1
