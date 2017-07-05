# bip38-cracker

Brute-force BIP38 cracker

## Installation
```bash
sudo apt-get update
sudo apt-get install -y git libssl-dev build-essential automake libglib2.0-dev libevent-dev libjansson-dev curl
git clone --recursive https://github.com/Dirbaio/bip38-cracker.git
cd bip38-cracker
cd picocoin
./autogen.sh
./configure
make
cd ..
touch README
./autogen.sh
./configure
make
```


## Usage

The cracker takes a currency id as the first argument, the BIP38 encrypted key as the second argument, and a list of passwords to try from stdin, one per line.

Thread count is hardcoded too, set it to your CPU count for maximum performance.

Pass the currency id as a parameter. btc, dgb, xpy are supported. Its simple to add further currencys.

```

### Examples
- Crack bitcoin key from a wordlist
```bash
./cracker btc 6Pf... < wordlist.txt
```
- Try all lowercase 5 letter passwords (uses gen.cpp to generate them all)
```bash
g++ gen.cpp -O2 -o gen
./gen aaaaa | ./cracker btc 6Pf...
```

## Note

- This probably leaks a bunch of memory and has a lot of bugs. For reference only.
