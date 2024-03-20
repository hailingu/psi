#include <stdio.h>
#include "psi.h"

int main() {

  char message[16] = "123456789012345";
  char slave[] = "1234567890";

  char master_key[64], public_key[2 * G_LENGTH + 1], private_key[32], system_key[2 * G_LENGTH + 1];
  char beta[2 * 32 + 1], alpha[2 * 32 + 1];
  beta[0] = '\0';
  alpha[0] = '\0';

  char blind_m[2 * G_LENGTH + 1];
  char unblind_m[2 * G_LENGTH + 1];
  char encrypted_m[2 * G_LENGTH + 1];
  char random[64];

  int r = random_seed_ch(random);
  if (r != 64) {
    printf("gen random number error\n");
    printf("%d\n", r);
    return -1;
  }

  // init system parameters
  printf("--------------------------------------------------\n");
  printf("Step 0: generate master key.\n");
  uint64_t ur = master_key_gen_ch(random, master_key);
  if (ur != SUCCESS) {
    printf("generate master key error, error number %d\n", r);
    return 0;
  }
  printf("OK\n");

  printf("--------------------------------------------------\n");
  printf("Step 1: generate public key and system key\n");
  ur = public_key_gen_from_master(master_key, slave, public_key, private_key);
  if (ur != SUCCESS) {
    printf("generate public private keys error, error number: %d", r);
    return 0;
  }
  printf("OK\n");

  printf("--------------------------------------------------\n");
  printf("Step 2: generate the system key\n");
  ur = system_key_gen_from_public_key(public_key, system_key);
  if (ur != SUCCESS) {
    printf("generate system key error, error number: %d", r);
    return 0;
  }
  printf("OK\n");

  // slave blind message
  printf("--------------------------------------------------\n");
  printf("Step 3: blind\n");
  r = random_seed_ch(random);
  if (r != 64) {
    printf("gen random number error\n");
    return 0;
  }
  ur = blind_ch(message, random, beta, system_key, blind_m);
  if (ur != SUCCESS) {
    printf("blind error, error number: %d", r);
    return 0;
  }
  printf("OK\n");

  // master encrypt message
  printf("--------------------------------------------------\n");
  printf("Step 4: encrypt\n");
  ur = encrypt_m(private_key, alpha, blind_m, encrypted_m);
  if (ur != SUCCESS) {
    printf("encrypt error, error number: %d", r);
    return 0;
  }
  printf("OK\n");

  // slave unblind
  printf("--------------------------------------------------\n");
  printf("Step 5: unblind\n");
  ur = unblind_alpha_beta(encrypted_m, alpha, beta, system_key, unblind_m);
  if (ur != SUCCESS) {
    printf("unblind error, error number: %d", r);
    return 0;
  }
  printf("OK\n");
  return 0;
}
