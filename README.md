# bitflipper
Combinatorially flip bits by brute force until a file is no longer corrupted.

## Building

You need to have openssl and zlib development packages installed.

Then just run `make`

## Running

Examples:

```bash
# 1 flip in corrupted file.
$ ./bitflipper examples/source.f8d0839dd728cb9a723e32058dcc386070d5e3b5.cpp.1flip.z f8d0839dd728cb9a723e32058dcc386070d5e3b5
Checking the uncompressed version
Found original file.  Saving to out.bin

# 2 flips in corrupted file.
$ ./bitflipper examples/test.dddd6ee7cc3af6ca5e814d9522acf57bb7b7cdc1.txt.2flips.z dddd6ee7cc3af6ca5e814d9522acf57bb7b7cdc1
Checking the uncompressed version
Found original file.  Saving to out.bin

# 3 bit flips in corrupted file.  This one takes ~ 10 seconds
$ ./bitflipper examples/test2.e35151d8fd6445f9361e4237bb282e707efe4090.txt.3flips.z e35151d8fd6445f9361e4237bb282e707efe4090
Checking the uncompressed version
Found original file.  Saving to out.bin
```

Make sure you are passing the zlib compressed version of the file as the first argument and just
the SHA1 hash in the second argument.

You can see the "corrupted" contents of each example:

* [Example 1](https://github.com/conorpp/bitflipper/blob/master/examples/source.f8d0839dd728cb9a723e32058dcc386070d5e3b5.cpp)
* [Example 2](https://github.com/conorpp/bitflipper/blob/master/examples/test.dddd6ee7cc3af6ca5e814d9522acf57bb7b7cdc1.txt)
* [Example 3](https://github.com/conorpp/bitflipper/blob/master/examples/test2.e35151d8fd6445f9361e4237bb282e707efe4090.txt)



