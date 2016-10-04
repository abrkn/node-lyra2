#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/Lyra2.h"
#include "lib/Sponge.h"

int main(int argc, char *argv[]) {
  int kLen = 32;
  unsigned char *K = malloc(kLen);

  unsigned char * pwd = (unsigned char *)strdup("the password");
  unsigned char * salt = (unsigned char *)strdup("the salt");

  int result = LYRA2(K, kLen, pwd, strlen(pwd), salt, strlen(salt), 2, 1000, 256);

  if (result != 0) {
    printf("lyra2 failed: %d", result);
    return 1;
  }

  int i;

  for (i = 0; i < kLen; i++) {
    printf("%02x", K[i]);
  }

  printf("\n");
}
