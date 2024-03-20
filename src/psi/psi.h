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

#ifndef PSI_ENCRYPTION_H_
#define PSI_ENCRYPTION_H_

#include "../../include/ecp_BN254.h"
#include "../../include/ecp2_BN254.h"
#include "../../include/fn_BN254.h"
#include "../../include/pair_BN254.h"
#include "../../include/hkdf.h"
#include "../../include/MurmurHash2.h"
#include "fcntl.h"
#include "string.h"
#include "time.h"
#include <unistd.h>

#define G_LENGTH (MODBYTES_256_56+1)

#define NULL_POINTER 2
#define nullptr NULL_POINTER

#define SUCCESS 0

/*
 * Function: hash
 * ----------------------------
 * Generate a hash
 *
 * [in]  m: the message to hash
 * [out] hashed_m: the hashed message
 */
void hash(char* m, char* hashed_m);

/*
 * Function: random_seed
 * ----------------------------
 *  Generate a random seed
 *
 *  returns: a random seed
 */
uint64_t random_seed();

/*
 * Function: random_seed_ch
 * ----------------------------
 * Generate a random seed
 *
 * [out] seed: the random seed
 *
 * returns: length of the seed
 */
int random_seed_ch(char* seed);

/*
 * Function: master_key_gen_ul
 * ----------------------------
 * Generate a master key based on a random seed
 *
 * [in]  seed: the random seed
 * [out] master_key: the master key
 *
 * returns: 0 if successful, 2 if nullptr
 */
uint64_t master_key_gen_ul(uint64_t seed, char* master_key);

/*
 * Function: master_key_gen_ch
 * ----------------------------
 * Generate a master key based on a random seed
 *
 * [in]  random: the random seed
 * [out] master_key: the master key
 *
 * returns: 0 if successful, 2 if nullptr
 */
uint64_t master_key_gen_ch(const char* seed, char* master_key);

/*
 * Function: public_key_gen_from_master
 * ----------------------------
 * Generate a key pair
 *
 * [in]  master_key: the master key
 * [in]  slave: the slave
 * [out] public_key: the public key of cyclic group
 * [out] private_key: the master private key
 *
 * returns: 0 if successful, 2 if nullptr
 */
uint64_t public_key_gen_from_master(
    char* master_key, char* slave, char* public_key, char* private_key);

/*
 * Function: system_key_gen_from_public_key
 * ----------------------------
 * Generate a system key from the public keys
 *
 * [in]  public_key: the public key of cyclic group
 * [out] system_key: the system key of cyclic group
 *
 * returns: 0 if successful, 2 if nullptr
 */
uint64_t system_key_gen_from_public_key(const char* public_key, char* system_key);

/*
 * Function: blind_ul
 * ----------------------------
 * Blind each did
 *
 * [in]  did: the did
 * [in]  seed: the random seed
 * [in]  beta: the beta
 * [in]  public_key: the public key
 * [out] m: the blinded did
 *
 * returns: 0 if successful, 2 if nullptr
 */
uint64_t blind_ul(char* did, uint64_t seed, char* beta, const char* public_key, char* m);

/*
 * Function: blind_ch
 * ----------------------------
 * Blind each did
 *
 * [in]  did: the did
 * [in]  seed: the random seed
 * [out] beta: the beta
 * [out] m: the blinded did
 *
 * returns: 0 if successful, 2 if nullptr
 */
uint64_t blind_ch(char* did, const char* seed, char* beta, const char* public_key, char* m);

/*
 * Function: unblind
 * ----------------------------
 * Unblind the massage
 *
 * [in]  blind_m: the blind message
 * [in]  beta: the beta
 * [in]  public_key: the public key of cyclic group
 * [out] unblind_m: the unblind_m did
 *
 * returns: 0 if successful, 2 if nullptr
 */
uint64_t unblind_beta(
    const char* blind_m,
    const char* beta,
    const char* public_key,
    char* unblind_m);

/*
 * Function: unblind_alpha_beta
 * ----------------------------
 * Unblind the massage
 *
 * [in]  blind_m: the blind message
 * [in]  beta: the beta
 * [in]  alpha: the alpha
 * [in]  public_key: the public key of cyclic group
 * [out] unblind_m: the unblind_m did
 *
 * returns: 0 if successful, 2 if nullptr
 */
uint64_t unblind_alpha_beta(
    const char* blind_m,
    const char* alpha,
    const char* beta,
    const char* public_key,
    char* unblind_m);

/*
 * Function: encrypt_m
 * ----------------------------
 * Encrypt the blinded message
 *
 * [in]  private_key: the private key
 * [out] alpha: the g^alpha
 * [in]  blind_m: the blinded message
 * [out] encrypted_m: the encrypted message
 *
 * returns: 0 if successful, 2 if nullptr
 */
uint64_t encrypt_m(
    char* private_key,
    char* alpha,
    const char* blind_m,
    char* encrypted_m);

/*
 * Function: encrypt_s
 * ----------------------------
 * Encrypt the blinded message
 *
 * [in]  alpha: the g^alpha
 * [in]  blind_m: the blinded message
 * [out] encrypted_m: the encrypted message
 *
 * returns: 0 if successful, 2 if nullptr
 */
uint64_t encrypt_s(char* alpha,
                   char* blind_m,
                   char* encrypted_m);

/*
 * Function: verify
 * ----------------------------
 * Verify the encrypted did
 *
 * [in]  encrypted_m: the encrypted did
 * [in]  public_key_g1: the public key of cyclic group
 * [in]  beta: the beta
 * [in]  did: the did
 *
 * returns: 0 if successful, 2 if nullptr
 */
int verify(const char* encrypted_m,
           const char* public_key,
           char* beta,
           char* did);

#endif // PSI_ENCRYPTION_H_
