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

The cracker takes the BIP38 encrypted key as first argument, and a list of passwords to try from stdin, one per line.

When the private key is recovered, the cracker will send a hardcoded amount of coins from it to a hardcoded address, using curl and blockchain API. I recommend you change the address to yours and set the amount to all the funds in the address minus the txfee.

Thread count is hardcoded too, set it to your CPU count for maximum performance.

### Examples
- Crack from a wordlist
```bash
./cracker 6Pf... < wordlist.txt
```
- Try all lowercase 5 letter passwords (uses gen.cpp to generate them all)
```bash
g++ gen.cpp -O2 -o gen
./gen aaaaa | ./cracker 6Pf...
```

## Note

- This probably leaks a bunch of memory and has a lot of bugs. For reference only.
