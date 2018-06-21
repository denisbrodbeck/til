# Create self-signed ECDSA certificates

TODO: clean article up

```bash
bash -c "openssl req -x509 -out dev.crt -keyout dev.key \
                 -newkey ec:<(openssl ecparam -genkey -name prime256v1) -nodes \
                 -subj '/CN=dev.mytestdomain.xy' -extensions EXT -config <( \
                  printf '[dn]\nCN=dev.mytestdomain.xy\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:dev1.mytestdomain.xy, DNS:dev2.mytestdomain.xy, DNS:dev3.mytestdomain.xy\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth')"
```

* `bash -c`: fish-shell doesn't support this kind of target redirection (`<(...)`)
* `-nodes`: Do not encrypt the key (meaning no password protection)

See [this example](https://golang.org/src/crypto/tls/generate_cert.go) from golang source showing how to create RSA or ECDSA certificates.
The project [minica](https://github.com/jsha/minica) creates an self-signed certificate authority and subsequently signs server certificates with the initially created ca.

[Certificates for localhost](https://letsencrypt.org/docs/certificates-for-localhost/)

See [Testing out ECDSA certificates](https://scotthelme.co.uk/ecdsa-certificates/) by [Scott Helme](https://scotthelme.co.uk) for further info on ECDSA certificates.
