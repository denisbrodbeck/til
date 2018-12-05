# Secure SSH

Good reference at [mozilla](https://infosec.mozilla.org/guidelines/openssh) and [stribika](https://stribika.github.io/2015/01/04/secure-secure-shell.html).

## Copy public key to server

```bash
ssh-copy-id -i .ssh/id_hosting.pub user@192.168.178.69
```

## Login with private key

```bash
ssh -i .ssh/id_hosting user@192.168.178.69
```

## Harden sshd_config

Edit `/etc/ssh/sshd_config`:

```text
Port 65333
HostKey /etc/ssh/ssh_host_ed25519_key
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
AuthenticationMethods publickey
AllowUsers it
LogLevel VERBOSE
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO
PermitRootLogin No
UsePrivilegeSeparation sandbox
TCPKeepAlive yes
PermitUserEnvironment no
AcceptEnv LANG LC_*
```
