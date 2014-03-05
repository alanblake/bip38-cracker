# bip38-cracker

Brute-force BIP38 cracker, originally by [@notespace](https://github.com/notespace) for [Casascius's BIP38 cracking contest](https://bitcointalk.org/index.php?topic=128699.0); repurposed by [@cscott](https://github.com/cscott) for [a similar reddit contest](http://www.reddit.com/r/Bitcoin/comments/1zkcya/lets_see_how_long_it_takes_to_crack_a_4_digit/).

If there is still a balance in [14kEQFm6d4RbRy1kqWTQ1gX84eBPpD9YLn](https://blockchain.info/address/14kEQFm6d4RbRy1kqWTQ1gX84eBPpD9YLn) the contest is still running!

## Usage

- Check out the `picocoin` and `scrypt-jane` submodules:
```bash
$ git submodule update --init
```

- Build libccoin inside of picocoin. I have removed the requirements to build the frontend, so it doesn't need a bunch of dependencies. I believe only openssl and glib. The bip38-cracker Makefile references libccoin.a .
```bash
$ cd picocoin
$ ./autogen.sh && ./configure && make
$ cd ..
```

- Build the main cracker binary.
```bash
$ ./autogen.sh && ./configure && make
```

- Run the cracker
```bash
$ ./cracker [optional starting string]
```

## Note

- This probably leaks a bunch of memory and has a lot of bugs. For reference only.
- The default implementation includes a key that decrypts with the password AaAaJ, so you can see how it runs without spending lots of time scrypt()ing.
