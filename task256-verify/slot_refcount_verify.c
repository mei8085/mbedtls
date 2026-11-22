/*
 * Local verification program for task-256:
 * PSA key-slot reference counting and concurrent destruction diagnostics.
 *
 * This is hand-written review code (not untrusted input). It exercises the
 * PSA Crypto API of the locally built tfpsacrypto library to verify:
 *
 *  A. Boundary key identifiers map to the documented error codes.
 *  B. A multipart operation keeps its own copy of the key material:
 *     destroying the key immediately after mac_sign_setup does not stop the
 *     in-flight operation, and psa_get_key_attributes() on the id fails.
 *  C. Concurrent destroy of the same key: exactly one thread succeeds and
 *     the others receive PSA_ERROR_INVALID_HANDLE (no corruption, no crash).
 *  D. Volatile-key purge is a no-op (the slot remains usable), while
 *     destroy makes the identifier invalid.
 */

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "psa/crypto.h"

#define CHECK(label, cond)                                              \
    do {                                                                \
        if (cond) {                                                     \
            printf("[ OK ] %s\n", label);                               \
        } else {                                                        \
            printf("[FAIL] %s (line %d)\n", label, __LINE__);           \
            failures++;                                                 \
        }                                                               \
    } while (0)

static int failures = 0;

static const unsigned char key_bytes[32] = {
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
};

/* ---- Test A: identifier boundary handling ------------------------------ */
static void test_id_boundaries(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t st;

    /* NULL id */
    st = psa_get_key_attributes(MBEDTLS_SVC_KEY_ID_INIT, &attr);
    CHECK("NULL key id -> INVALID_HANDLE", st == PSA_ERROR_INVALID_HANDLE);

    /* User-range id that was never created */
    st = psa_get_key_attributes(mbedtls_svc_key_id_make(0, 0x00000001), &attr);
    CHECK("non-existent user id -> INVALID_HANDLE",
          st == PSA_ERROR_INVALID_HANDLE);

    /* Vendor id below the volatile minimum and outside builtin range:
     * 0x40000000 is PSA_KEY_ID_VOLATILE_MIN; try an out-of-range high id
     * 0x7fffffff (VENDOR_MAX) which is not builtin (builtin max 0x7fffefff). */
    st = psa_get_key_attributes(mbedtls_svc_key_id_make(0, 0x7fffffff), &attr);
    CHECK("out-of-range vendor id -> INVALID_HANDLE",
          st == PSA_ERROR_INVALID_HANDLE);

    /* Destroying the NULL key id is specified to succeed. */
    st = psa_destroy_key(MBEDTLS_SVC_KEY_ID_INIT);
    CHECK("destroy NULL id -> SUCCESS", st == PSA_SUCCESS);

    psa_reset_key_attributes(&attr);
}

/* ---- Test B: multipart operation retains a key copy -------------------- */
static void test_multipart_key_copy(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    psa_key_id_t key;
    unsigned char mac[PSA_MAC_MAX_SIZE];
    size_t mac_len;
    psa_status_t st;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH |
                                   PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_CMAC);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    st = psa_import_key(&attr, key_bytes, sizeof(key_bytes), &key);
    CHECK("import AES key for CMAC", st == PSA_SUCCESS);
    psa_reset_key_attributes(&attr);

    /* Setup registers a reader, copies key material into the operation,
     * then unregisters. */
    st = psa_mac_sign_setup(&op, key, PSA_ALG_CMAC);
    CHECK("mac_sign_setup", st == PSA_SUCCESS);

    /* Destroy the slot while the multipart operation is in flight. */
    st = psa_destroy_key(key);
    CHECK("destroy key while MAC op in flight -> SUCCESS", st == PSA_SUCCESS);

    /* The identifier must now be invalid even though the op lives on. */
    psa_key_attributes_t got = PSA_KEY_ATTRIBUTES_INIT;
    st = psa_get_key_attributes(key, &got);
    CHECK("id invalid after destroy (op still in flight)",
          st == PSA_ERROR_INVALID_HANDLE);
    psa_reset_key_attributes(&got);

    /* The operation must still complete: it works on its own copy. */
    st = psa_mac_update(&op, (const unsigned char *) "abc", 3);
    CHECK("mac_update after destroy -> SUCCESS", st == PSA_SUCCESS);
    st = psa_mac_sign_finish(&op, mac, sizeof(mac), &mac_len);
    CHECK("mac_sign_finish after destroy -> SUCCESS (key copy lingers)",
          st == PSA_SUCCESS);
    psa_mac_abort(&op);
}

/* ---- Test C: exactly one concurrent destroyer wins --------------------- */
typedef struct {
    psa_key_id_t key;
    int success_count;
    pthread_mutex_t lock;
} destroy_ctx_t;

static void *destroyer(void *arg)
{
    destroy_ctx_t *ctx = (destroy_ctx_t *) arg;
    psa_status_t st = psa_destroy_key(ctx->key);
    if (st == PSA_SUCCESS) {
        pthread_mutex_lock(&ctx->lock);
        ctx->success_count++;
        pthread_mutex_unlock(&ctx->lock);
    } else if (st != PSA_ERROR_INVALID_HANDLE) {
        printf("[FAIL] unexpected destroy status %d\n", (int) st);
        failures++;
    }
    return NULL;
}

static void test_concurrent_destroy(void)
{
    enum { N = 8 };
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    destroy_ctx_t ctx;
    pthread_t th[N];
    psa_status_t st;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_CMAC);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    st = psa_import_key(&attr, key_bytes, sizeof(key_bytes), &ctx.key);
    CHECK("import key for concurrent destroy", st == PSA_SUCCESS);
    psa_reset_key_attributes(&attr);

    ctx.success_count = 0;
    pthread_mutex_init(&ctx.lock, NULL);

    for (int i = 0; i < N; i++) {
        pthread_create(&th[i], NULL, destroyer, &ctx);
    }
    for (int i = 0; i < N; i++) {
        pthread_join(th[i], NULL);
    }
    pthread_mutex_destroy(&ctx.lock);

    CHECK("exactly one of 8 concurrent destroy calls succeeded",
          ctx.success_count == 1);

    psa_key_attributes_t got = PSA_KEY_ATTRIBUTES_INIT;
    st = psa_get_key_attributes(ctx.key, &got);
    CHECK("key gone after concurrent destroy",
          st == PSA_ERROR_INVALID_HANDLE);
    psa_reset_key_attributes(&got);
}

/* ---- Test D: purge semantics on volatile keys -------------------------- */
static void test_purge_volatile(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key;
    psa_status_t st;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_CMAC);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    st = psa_import_key(&attr, key_bytes, sizeof(key_bytes), &key);
    CHECK("import volatile key", st == PSA_SUCCESS);
    psa_reset_key_attributes(&attr);

    st = psa_purge_key(key);
    CHECK("purge volatile key -> SUCCESS (no-op for volatile lifetime)",
          st == PSA_SUCCESS);

    psa_key_attributes_t got = PSA_KEY_ATTRIBUTES_INIT;
    st = psa_get_key_attributes(key, &got);
    CHECK("volatile key still valid after purge", st == PSA_SUCCESS);
    psa_reset_key_attributes(&got);

    st = psa_destroy_key(key);
    CHECK("destroy volatile key", st == PSA_SUCCESS);
    st = psa_get_key_attributes(key, &got);
    CHECK("volatile key invalid after destroy",
          st == PSA_ERROR_INVALID_HANDLE);
}

int main(void)
{
    psa_status_t st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        printf("psa_crypto_init failed: %d\n", (int) st);
        return 2;
    }

    test_id_boundaries();
    test_multipart_key_copy();
    test_concurrent_destroy();
    test_purge_volatile();

    mbedtls_psa_crypto_free();

    if (failures == 0) {
        printf("\nALL LOCAL CHECKS PASSED\n");
        return 0;
    }
    printf("\n%d CHECK(S) FAILED\n", failures);
    return 1;
}
