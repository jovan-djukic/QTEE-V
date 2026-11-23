/*
 * Generate one simulated QTEE-V relay device: a secret 32-byte root-key seed
 * and the matching Keystone device public key (PK_D).
 *
 * Keystone's Ed25519 hashes with SHA3-512 instead of SHA-512, so the public
 * key is derived here with the boot ROM's own code (external/keystone/bootrom
 * ed25519/ and sha3/): exactly what bootloader.c computes from the same seed.
 *
 * Usage: gen_device_key <seed-out> <pub-out>
 *   <seed-out>  32 raw bytes, created mode 0600. QEMU loads it into the
 *               device's secret-key slot (see tools/make_devices.sh). It is
 *               the device's root secret: per-device, but a plain host file,
 *               not hardware-protected.
 *   <pub-out>   PK_D as 64 hex chars + newline, for controller.py --device-key.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define ED25519_NO_SEED 1
#include "ed25519/ed25519.h"

static int write_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

int main(int argc, char **argv) {
    unsigned char seed[32], pk[32], sk[64];
    if (argc != 3) {
        fprintf(stderr, "usage: %s <seed-out> <pub-out>\n", argv[0]);
        return 2;
    }

    int r = open("/dev/urandom", O_RDONLY);
    if (r < 0 || read(r, seed, sizeof seed) != (ssize_t)sizeof seed) {
        perror("/dev/urandom");
        return 1;
    }
    close(r);
    /* The boot ROM treats an all-zero slot as "no seed" (test-key fallback). */
    unsigned char any = 0;
    for (size_t i = 0; i < sizeof seed; i++) any |= seed[i];
    if (!any) { fprintf(stderr, "all-zero seed, retry\n"); return 1; }

    ed25519_create_keypair(pk, sk, seed);

    int fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || write_all(fd, seed, sizeof seed) || close(fd)) {
        perror(argv[1]);
        return 1;
    }
    FILE *f = fopen(argv[2], "w");
    if (!f) { perror(argv[2]); return 1; }
    for (size_t i = 0; i < sizeof pk; i++) fprintf(f, "%02x", pk[i]);
    fprintf(f, "\n");
    if (fclose(f)) { perror(argv[2]); return 1; }

    memset(seed, 0, sizeof seed);
    memset(sk, 0, sizeof sk);
    return 0;
}
