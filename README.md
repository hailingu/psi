# PSI

Fork from SecureUnionID project, Bytedance.

## Build

```shell
cd build
# search CMakeLists.txt in parent directory
cmake ..
# build project
make
# run
./psi
```

## Usage

1. master: generate a random. see [`random_seed_ch`]()
2. master: use the random to generate a master key. see [`master_key_gen_ch`]()
3. master: use the master key to generate a public key and a private key. see [`public_key_gen_from_master`]()
4. slave: see [`blind_ch`]()
   1. generate a random
   2. use the random and the public key to generate a beta
5. master: see [`encrypt_m`]()
   1. generate a random
   2. use the random and the private key to generate an alpha
   3. use the alpha to encrypt the message received from slave
   4. send the encrypted message and the alpha back to slave
6. slave: use alpha and beta to unblind the message. see [`unblind_alpha_beta`]()

## Perf

Total 3,000,000 blind, enc, unblind loop, on a 2.3 GHz 8-Core Intel Core i9 OSX.

| Program | Encrypt Perf(d/s/t) | With Thread                     |    
|---------|---------------------|---------------------------------|
| PRL     | 744.071931          | -                               |
| PSI     | 2700-6500.748107    | 17158.167686-65111.440835 (15t) |

