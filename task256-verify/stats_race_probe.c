/*
 * Targeted check for task-256: concurrent psa_destroy_key() vs the
 * diagnostics interface mbedtls_psa_get_stats().
 *
 * Code reading shows mbedtls_psa_get_stats() traverses all key slots and
 * reads slot->state / slot->registered_readers without taking
 * mbedtls_threading_key_slot_mutex, while every mutation of those fields
 * happens under that mutex. This program runs destroyers and a stats reader
 * concurrently under ThreadSanitizer to see whether the unsynchronized reads
 * are observable as data races.
 *
 * Hand-written review code (not untrusted input).
 */

#include <stdio.h>
#include <pthread.h>
#include "psa/crypto.h"

static const unsigned char kb[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static volatile int stop;

static void *stats_reader(void *arg)
{
    (void) arg;
    mbedtls_psa_stats_t s;
    while (!stop) {
        mbedtls_psa_get_stats(&s);   /* no mutex taken internally */
    }
    return NULL;
}

static void *destroyer(void *arg)
{
    psa_key_id_t *ids = (psa_key_id_t *) arg;
    for (int i = 0; i < 64; i++) {
        (void) psa_destroy_key(ids[i]);
    }
    return NULL;
}

int main(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return 2;
    }

    enum { NKEYS = 64, NTHR = 4 };
    static psa_key_id_t ids[NKEYS];
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_CMAC);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    pthread_t reader;
    pthread_t th[NTHR];

    /* Repeated rounds create keys, then race stats-reading vs destruction. */
    for (int round = 0; round < 20; round++) {
        for (int i = 0; i < NKEYS; i++) {
            if (psa_import_key(&attr, kb, sizeof(kb), &ids[i]) != PSA_SUCCESS) {
                printf("import failed round %d key %d\n", round, i);
                return 1;
            }
        }
        stop = 0;
        pthread_create(&reader, NULL, stats_reader, NULL);
        for (int t = 0; t < NTHR; t++) {
            pthread_create(&th[t], NULL, destroyer, ids);
        }
        for (int t = 0; t < NTHR; t++) {
            pthread_join(th[t], NULL);
        }
        stop = 1;
        pthread_join(reader, NULL);
    }

    psa_reset_key_attributes(&attr);
    mbedtls_psa_crypto_free();
    printf("stats-vs-destroy race probe finished (inspect TSan output above)\n");
    return 0;
}
