# SourCerts

A Test to ascertain the feasibility of using eBPF to monitor SSL certificate
expirations. This test uses a uretprobe on OpenSSL's libssl to introspect the certificate
of any application using libssl and making a call to `SSL_get_peer_certificate`.

Next steps would be to return the subject of the certificate as well and explore
the feasibility for other SSL implementations.

## build

```
make build
```

## run

```
sudo ./sourcerts
./tests/https_get.rb
```
