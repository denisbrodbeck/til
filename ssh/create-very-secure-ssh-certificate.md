# Create very secure ed25519 ssh certificates

```bash
ssh-keygen -a 100 -t ed25519 -C "Your Name | 2018-12-05 | dev"
```

Note: Flag `-t ed25519` uses flag `-o` implicitly.

## Windows support with Putty

Official Putty version 0.7 can't convert ed25519 private keys. Use the Putty version from [snapshot](https://www.chiark.greenend.org.uk/~sgtatham/putty/snapshot.html) instead.
