// Copyright 2024 The SecureUnionID Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <time.h>
#include "psi.h"

void BN254_HASH(ECP_BN254* P, char* m) {
  int i;
  sha3 hs;
  char h[MODBYTES_256_56];
  octet HM = {MODBYTES_256_56, sizeof(h), h};
  // get random value of 32 bytes with sha3
  SHA3_init(&hs, SHAKE256);
  for (i = 0; m[i] != 0; i++) {
    SHA3_process(&hs, m[i]);
  }
  SHA3_shake(&hs, HM.val, MODBYTES_256_56);
  // map the octet object HM into G
  ECP_BN254_mapit(P, &HM);
} // BN254_HASH

/* serialize G element */
void g_serialize(ECP_BN254 G, char* g) {
  int i;
  char c[2 * MODBYTES_256_56 + 1];
  octet C = {0, sizeof(c), c};
  // convert the G element into octet format
  ECP_BN254_toOctet(&C, &G, true);
  for (i = 0; i < C.len; ++i) {
    // format
    sprintf(g + i * 2, "%02x", (unsigned char) C.val[i]);
  }
  g[2 * C.len] = '\0';
} // g_serialize

/* deserialize G */
void g_deserialize(ECP_BN254* G, const char* g) {
  char c[2 * MODBYTES_256_56 + 1];
  unsigned long bytes;
  int counter = 0;
  octet C = {0, sizeof(c), c};
  C.len = MODBYTES_256_56 + 1;
  char temp[3];
  temp[2] = '\0';
  // convert the string into octet format
  for (int j = 0; j < 2 * C.len; j += 2) {
    if (0 == j % 2) {
      temp[0] = g[j];
      temp[1] = g[j + 1];
      bytes = strtoul(temp, 0, 16);
      C.val[counter] = (char) bytes;
      counter++;
    }
  }
  // convert octet format into G element
  ECP_BN254_fromOctet(G, &C);
} // g_deserialize

/* serialize BIG element */
void big_serialize(BIG_256_56 BIG, char* big) {
  int i;
  char big_byte[MODBYTES_256_56];
  BIG_256_56_toBytes(big_byte, BIG);
  for (i = 0; i < MODBYTES_256_56; i++) {
    sprintf(big + i * 2, "%02x", (unsigned char) big_byte[i]);
  }
  big[2 * MODBYTES_256_56] = '\0';
} // big_serialize

/* deserialize BIG element */
void big_deserialize(BIG_256_56 BIG, const char* big) {
  char big_byte[MODBYTES_256_56];
  int counter = 0, j;
  char temp[3];
  temp[2] = '\0'; // use strtoul must end with '\0'
  unsigned int bytes;
  // convert the string into bytes[]
  for (j = 0; j < 2 * MODBYTES_256_56; j += 2) {
    if (0 == j % 2) {
      temp[0] = big[j];
      temp[1] = big[j + 1];
      bytes = strtoul(temp, 0, 16);
      big_byte[counter] = (char) bytes;
      counter++;
    }
  }
  // convert the bytes[] to BIG element
  BIG_256_56_fromBytes(BIG, big_byte);
} // big_deserialize

void hash(char* m, char* hashed_m) {
  ECP_BN254 P;
  sha3 hs;
  char h[MODBYTES_256_56];
  octet HM = {MODBYTES_256_56, sizeof(h), h};
  // get random value of 32 bytes with sha3
  SHA3_init(&hs, SHAKE256);
  for (int i = 0; m[i] != 0; ++i) {
    SHA3_process(&hs, m[i]);
  }

  SHA3_shake(&hs, HM.val, MODBYTES_256_56);
  // map the octet object HM into G
  ECP_BN254_mapit(&P, &HM);
  g_serialize(P, hashed_m);
} // hash

uint64_t random_seed() {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  unsigned long time_in_mill =
      (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);

  return MurmurHash64A(&time_in_mill, sizeof(time_in_mill), 0);
} // random_seed


int random_seed_ch(char* seed) {
  if (!seed) {
    return nullptr;
  }

  int length = 0;
  while (length != 64) {
    memmove(&seed[length], &random_seed, 8);
    length += 8;
  }

  return length;
} // random_seed_ch


uint64_t master_key_gen_ul(uint64_t random, char* master_key) {
  if (!master_key) {
    return nullptr;
  }
  int i;
  char raw[100];
  csprng rng;
  octet RAW = {0, sizeof(raw), raw};

  RAW.len = 100; // fake random seed source
  RAW.val[0] = (char) random;
  RAW.val[1] = (char) (random >> 8);
  RAW.val[2] = (char) (random >> 16);
  RAW.val[3] = (char) (random >> 24);
  for (i = 4; i < 100; i++) {
    RAW.val[i] = (char) i;
  }
  CREATE_CSPRNG(&rng, &RAW); // initialise strong RNG

  for (i = 0; i < 64; i++) {
    master_key[i] = (char) RAND_byte(&rng);
  }

  return SUCCESS;
} // master_key_gen_ul

uint64_t master_key_gen_ch(const char* random, char* master_key) {
  if (!master_key || !random) {
    return nullptr;
  }

  int i;
  char raw[64];
  csprng rng;
  octet RAW = {0, sizeof(raw), raw};

  // fake random seed source
  RAW.len = 64;
  for (i = 0; i < 64; ++i) {
    RAW.val[i] = random[i];
  }
  // initialise strong RNG
  CREATE_CSPRNG(&rng, &RAW);

  for (i = 0; i < 64; i++) {
    master_key[i] = (char) RAND_byte(&rng);
  }
  return SUCCESS;
} // master_key_gen_char

uint64_t public_key_gen_from_master(
    char* master_key,
    char* slave,
    char* public_key,
    char* private_key
) {
  if (!master_key || !slave || !public_key || !private_key) {
    return nullptr;
  }
  char g[G_LENGTH * 2 + 1];
  ECP_BN254 _g;
  BIG_256_56 alpha, _q;

  HKDF((unsigned char*) master_key,
       64,
       (unsigned char*) slave,
       (int) strlen(slave),
       (unsigned char*) private_key);
  BIG_256_56_fromBytes(alpha, private_key);
  BIG_256_56_rcopy(_q, CURVE_Order_BN254);
  BIG_256_56_mod(alpha, _q);

  // public_key = g^alpha
  g_deserialize(&_g, g);

  // serialize the public key and store it into pk string */
  g_serialize(_g, public_key);
  return SUCCESS;
} // public_key_gen_from_master

uint64_t system_key_gen_from_public_key(const char* public_key, char* system_key) {
  if (!public_key || !system_key) {
    return nullptr;
  }
  ECP_BN254 _s, _p;

  // set the system parameter to be zero, ie, the infinity pointer.
  ECP_BN254_inf(&_s);

  // deserialize the public key for the i th media.
  g_deserialize(&_p, public_key);
  ECP_BN254_add(&_s, &_p);

  // system_key = 0*g
  g_serialize(_s, system_key);
  return SUCCESS;
} // system_key_gen_from_public_key

uint64_t blind_ul(
    char* did,
    uint64_t seed,
    char* beta,
    const char* public_key,
    char* m
) {
  if (!did || !beta || !m) {
    return nullptr;
  }

  char raw[100];
  octet RAW = {0, sizeof(raw), raw};
  ECP_BN254 _did, M;
  BIG_256_56 _q, BIG_BETA;
  int i;

  // generate the random seed.
  csprng rng;
  RAW.len = 100;
  RAW.val[0] = (char) seed;
  RAW.val[1] = (char) (seed >> 8);
  RAW.val[2] = (char) (seed >> 16);
  RAW.val[3] = (char) (seed >> 24);
  for (i = 4; i < 100; ++i) {
    RAW.val[i] = (char) i;
  }

  // initialise strong RNG
  CREATE_CSPRNG(&rng, &RAW);

  // generate the random BIG number for blinding
  BIG_256_56_rcopy(_q, CURVE_Order_BN254);
  BIG_256_56_randomnum(BIG_BETA, _q, &rng);
  big_serialize(BIG_BETA, beta);

  BN254_HASH(&_did, did);

  g_deserialize(&M, public_key);
  ECP_BN254_mul(&M, BIG_BETA);
  ECP_BN254_add(&M, &_did);

  // serialize M
  g_serialize(M, m);
  return SUCCESS;
} // blind_ul

uint64_t blind_ch(char* did,
                  const char* seed,
                  char* beta,
                  const char* public_key,
                  char* m
) {
  if (!did || !seed || !beta || !m) {
    return nullptr;
  }

  char raw[64];
  octet RAW = {0, sizeof(raw), raw};
  ECP_BN254 _did, M;
  BIG_256_56 _q, BIG_BETA;

  if (beta[0] != '\0') {
    // generate the random seed
    csprng rng;
    RAW.len = 64;
    for (int i = 0; i < 64; ++i) {
      RAW.val[i] = seed[i];
    }
    CREATE_CSPRNG(&rng, &RAW);

    // generate the random BIG number for blinding
    BIG_256_56_rcopy(_q, CURVE_Order_BN254);
    BIG_256_56_randomnum(BIG_BETA, _q, &rng);
    big_serialize(BIG_BETA, beta);
  } else {
    big_deserialize(BIG_BETA, beta);
  }

  // _did = H(did),  serialize _did into m.
  BN254_HASH(&_did, did);

  // build default g
  g_deserialize(&M, public_key);

  // M = g^BIG_BETA
  ECP_BN254_mul(&M, BIG_BETA);

  // m = (g^BIG_BETA) * _did
  ECP_BN254_add(&M, &_did);
  g_serialize(M, m);
  return SUCCESS;
} // blind_ch

uint64_t unblind_beta(
    const char* blind_m,
    const char* beta,
    const char* public_key,
    char* unblind_m
) {
  if (!blind_m || !beta || !public_key || !unblind_m) {
    return nullptr;
  }

  ECP_BN254 M, Q;
  BIG_256_56 BIG_BETA;

  // restore encrypted message into M, M = (g^BIG_BETA) * _did
  g_deserialize(&M, blind_m);

  // restore beta into big_beta;
  big_deserialize(BIG_BETA, beta);

  // Q = g^(big_beta)
  g_deserialize(&Q, public_key);
  ECP_BN254_mul(&Q, BIG_BETA);
  // Q = -g^(big_beta)
  ECP_BN254_neg(&Q);

  // Q = M * Q = -g^(big_beta) * M
  ECP_BN254_add(&Q, &M);

  // store the result
  g_serialize(Q, unblind_m);

  return SUCCESS;
} // unblind

uint64_t unblind_alpha_beta(
    const char* blind_m,
    const char* alpha,
    const char* beta,
    const char* public_key,
    char* unblind_m
) {
  if (!blind_m || !beta || !public_key || !unblind_m) {
    return nullptr;
  }

  ECP_BN254 M, Q;
  BIG_256_56 BIG_BETA, BIG_ALPHA;

  // restore encrypted message into M, M = (g^BIG_BETA) * _did
  g_deserialize(&M, blind_m);

  // restore beta into big_beta;
  big_deserialize(BIG_BETA, beta);
  big_deserialize(BIG_ALPHA, alpha);

  // Q = g^(big_beta)
  g_deserialize(&Q, public_key);
  ECP_BN254_mul(&Q, BIG_BETA);
  ECP_BN254_mul(&Q, BIG_ALPHA);

  // Q = -g^(big_beta)^(big_alpha)
  ECP_BN254_neg(&Q);

  // M = hash_did^big_alpha * (g^big_beta^big_alpha)
  // Q = M * Q = -g^(big_beta)^(big_alpha) * hash_did^big_alpha * (g^big_beta^big_alpha)
  //   = hash_did^big_alpha
  ECP_BN254_add(&Q, &M);

  // store the result
  g_serialize(Q, unblind_m);

  return SUCCESS;
} // unblind

uint64_t encrypt_m(
    char* private_key,
    char* alpha,
    const char* blind_m,
    char* encrypted_m
) {
  if (!private_key || !alpha || !blind_m || !encrypted_m) {
    return nullptr;
  }

  BIG_256_56 BIG_ALPHA, q;
  ECP_BN254 M;

  if (alpha[0] != '\0') {
    BIG_256_56_fromBytes(BIG_ALPHA, private_key);
    BIG_256_56_rcopy(q, CURVE_Order_BN254);
    BIG_256_56_mod(BIG_ALPHA, q);
    big_serialize(BIG_ALPHA, alpha);
  } else {
    big_deserialize(BIG_ALPHA, alpha);
  }

  // deserialize m and store it into M, M = (g^big_beta) * hash_did
  g_deserialize(&M, blind_m);
  // M = blind_m, M = hash_did^big_alpha * (g^big_beta^big_alpha)
  ECP_BN254_mul(&M, BIG_ALPHA);
  g_serialize(M, encrypted_m);
  return SUCCESS;
} // encrypt_m

uint64_t encrypt_s(
    char* alpha,
    char* blind_m,
    char* encrypted_m
) {
  if (!alpha || !blind_m || !encrypted_m) {
    return nullptr;
  }

  BIG_256_56 BIG_ALPHA;
  ECP_BN254 M;

  big_deserialize(BIG_ALPHA, alpha);

  // deserialize m and store it into M, M =  hash_did
  g_deserialize(&M, blind_m);
  // M = _did^big_alpha
  ECP_BN254_mul(&M, BIG_ALPHA);
  g_serialize(M, encrypted_m);
  return SUCCESS;
}
