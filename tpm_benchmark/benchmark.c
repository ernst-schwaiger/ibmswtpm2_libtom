#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_param_enc.h>

#include <examples/native/native_test.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#define MAX_STM32TPM_RSA_KEY_BITS               (3072U)
#define STM32TPM_BENCHMARK_RSA_1024_KEY_BITS    (1024U)
#define STM32TPM_BENCHMARK_RSA_2048_KEY_BITS    (2048U)
#define STM32TPM_BENCHMARK_RSA_2048_OAEP_ENC_BYTES ((STM32TPM_BENCHMARK_RSA_2048_KEY_BITS - (2 * 256) - 16) / 8)
#define STM32TPM_BENCHMARK_RSA_2048_SEAL_BYTES  (128U)
#define STM32TPM_BENCHMARK_AES_256_ENC_BYTES    (256U)
#define STM32TPM_BENCHMARK_AES_256_HMAC_BYTES   (256U)
#define STM32TPM_BENCHMARK_SHA_256_DATA_BYTES   (256U)

#define BENCHMARK_NUM_LOOPS                     (500U)
#define MAX_NUM_MEASURED_COMMANDS               (10000U)

/* Commands to measure */
#define TPM_CC_HASHSEQUENCESTART    0x00000186
#define TPM_CC_SEQUENCEUPDATE       0x0000015C
#define TPM_CC_SEQUENCECOMPLETE     0x0000013E
#define TPM_CC_CREATE               0x00000153
#define TPM_CC_STARTUP              0x00000144
#define TPM_CC_SHUTDOWN             0x00000145
#define TPM_CC_RSA_ENCRYPT          0x00000174
#define TPM_CC_RSA_DECRYPT          0x00000159
#define TPM_CC_ENCRYPTDECRYPT2      0x00000193
#define TPM_CC_SIGN                 0x0000015D
#define TPM_CC_VERIFYSIGNATURE      0x00000177
#define TPM_CC_HMAC                 0x00000155
#define TPM_CC_UNSEAL               0x0000015E

#define LOG(s) do { fprintf(stdout, s); fflush(stdout); } while(0)

#define MEASURE_START(c) do { measurement.command = c; clock_gettime(CLOCK_MONOTONIC_RAW, &measurement.start_time); } while(0)
#define MEASURE_FINISH() do { clock_gettime(CLOCK_MONOTONIC_RAW, &measurement.finish_time); add_measurement(); } while(0)

typedef struct tpmKey {
    TPM_HANDLE          handle;
    TPM2B_AUTH          auth;
    TPMT_SYM_DEF_OBJECT symmetric; /* used for parameter encrypt/decrypt */
    TPM2B_PRIVATE       priv;
    TPM2B_PUBLIC        pub;
    TPM2B_NAME          name;
    TPM2B_DIGEST        creationHash;
    TPMT_TK_CREATION    creationTicket;
} TpmKey;

typedef TpmKey TpmRsaKey;

TPM2_AUTH_SESSION session[MAX_SESSION_NUM];

typedef struct
{
    struct timespec start_time;
    struct timespec finish_time;
    uint32_t command;
} measurement_t;

typedef struct
{
    uint32_t duration_us;
    uint32_t command;
} measured_command_t;

static measurement_t measurement;
static measured_command_t measured_commands[MAX_NUM_MEASURED_COMMANDS];
static uint32_t command_index = 0;

static void add_measurement()
{
    int32_t diff_seconds = measurement.finish_time.tv_sec - measurement.start_time.tv_sec;
    int32_t diff_ns = measurement.finish_time.tv_nsec - measurement.start_time.tv_nsec; /* at most +- 1 billion - 1 */

    if (diff_ns < 0)
    {
        diff_seconds--;
        diff_ns += 1000000000;
    }

    int32_t duration_us = (diff_seconds * 1000000) + (diff_ns / 1000);

    measured_commands[command_index].duration_us = duration_us;
    measured_commands[command_index].command = measurement.command;
    command_index++;

    if (command_index >= MAX_NUM_MEASURED_COMMANDS)
    {
        fprintf(stderr, "exceeded number of measured events, rolling over!\n");
        command_index = 0;
    }
}

static void export_measurements()
{
    FILE *f = fopen("command_benchmark_client.csv","w");

    if (f == NULL)
    {
        fprintf(stderr, "Could not open file command_benchmark_client.csv for writing!\n");
        return;
    }

    for (uint32_t idx = 0; idx < command_index; idx++)
    {
        fprintf(f, "%d,0x%x\n", measured_commands[idx].duration_us, measured_commands[idx].command);
    }

    fclose(f);
    printf("Stored measured command durations in command_benchmark_client.csv\n");
}

static void init_random()
{
    struct timespec curr_time;
    clock_gettime(CLOCK_MONOTONIC_RAW, &curr_time);
    int seed = (int)curr_time.tv_nsec;
    srand(seed);
}

static void fill_random(uint8_t *buf, size_t length)
{
    int rnd;
    size_t num_bytes_rnd = sizeof(rnd);
    while (length >= num_bytes_rnd)
    {
        rnd = rand();
        memcpy(buf, (void *)&rnd, num_bytes_rnd);
        buf = &buf[num_bytes_rnd];
        length -= num_bytes_rnd;
    }

    rnd = rand();
    memcpy(buf, (void *)&rnd, length);
}

static void generate_unique_message(uint8_t *buf, size_t length, size_t msg_idx)
{
    // Fill the whole buffer
    XMEMSET(buf, (uint8_t)msg_idx, length);
    // Putting the complete index at the beginning of the message makes it unique
    memcpy(buf, (void *)&msg_idx, sizeof(msg_idx));
}

static int create_primary_null_rsa_2048(TpmRsaKey *null_primary_key)
{
    int rc;

    CreatePrimary_In createPriIn;
    CreatePrimary_Out createPriOut;

    /* Create Primary (Null Hierarchy) */
    XMEMSET(&createPriIn, 0, sizeof(createPriIn));
    createPriIn.primaryHandle = TPM_RH_NULL;
    
    // We use a zero-size password for accessing the NULL hierarchy
    createPriIn.inPublic.publicArea.authPolicy.size = 0;
    createPriIn.inPublic.publicArea.type = TPM_ALG_RSA;

    // For the key creation benchmark, we use only 1024 bit keys to speed up the process
    createPriIn.inPublic.publicArea.unique.rsa.size = STM32TPM_BENCHMARK_RSA_2048_KEY_BITS / 8;
    createPriIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createPriIn.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt);
    createPriIn.inPublic.publicArea.parameters.rsaDetail.keyBits = STM32TPM_BENCHMARK_RSA_2048_KEY_BITS;
    createPriIn.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    createPriIn.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    createPriIn.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    createPriIn.inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    createPriIn.inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    rc = TPM2_CreatePrimary(&createPriIn, &createPriOut);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }
    
    null_primary_key->handle = createPriOut.objectHandle;
    null_primary_key->auth = createPriIn.inPublic.publicArea.authPolicy;
    null_primary_key->pub = createPriOut.outPublic;
    null_primary_key->name = createPriOut.name;
    null_primary_key->symmetric = createPriIn.inPublic.publicArea.parameters.rsaDetail.symmetric;

    return TPM_RC_SUCCESS;
}

static int create_enc_key_rsa(TpmRsaKey const *parent_key,size_t rsa_key_length)
{
    int rc;
    Create_In createIn;
    Create_Out createOut;
    uint8_t keyCreationNonce[32];
    fill_random(keyCreationNonce, sizeof(keyCreationNonce));

    /* Create an RSA key for encrypt/decrypt, below the primary key of the NULL hierarchy */
    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent_key->handle;
    
    // We use a zero-size password for accessing the NULL hierarchy
    createIn.inSensitive.sensitive.userAuth.size = 0;
    
    // For the key creation benchmark, we use only 1024 bit keys to speed up the process
    createIn.inPublic.publicArea.type = TPM_ALG_RSA;
    createIn.inPublic.publicArea.unique.rsa.size = rsa_key_length / 8;
    createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA );
    createIn.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    createIn.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    createIn.inPublic.publicArea.parameters.rsaDetail.keyBits = rsa_key_length;
    createIn.outsideInfo.size = sizeof(keyCreationNonce)-1;
    XMEMCPY(createIn.outsideInfo.buffer, keyCreationNonce, createIn.outsideInfo.size);

    // We dont to anthing with the key here; we just measure the time it takes to create it
    MEASURE_START(TPM_CC_CREATE);
    rc = TPM2_Create(&createIn, &createOut);
    MEASURE_FINISH();

    return rc;
}

static int create_key_ecc_nistp_256(TpmRsaKey const *parent_key)
{
    int rc;
    Create_In createIn;
    Create_Out createOut;

    /* Create an ECC key for ECDH */
    /* Create an ECC key for encrypt/decrypt, below the primary key of the NULL hierarchy */
    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent_key->handle;
    
    // We use a zero-size password for accessing the NULL hierarchy
    createIn.inSensitive.sensitive.userAuth.size = 0;
    createIn.inPublic.publicArea.type = TPM_ALG_ECC;
    createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA);
    createIn.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    createIn.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDH;
    createIn.inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    createIn.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

    // We just measure the time to create the ECC key here
    MEASURE_START(TPM_CC_CREATE);
    rc = TPM2_Create(&createIn, &createOut);
    MEASURE_FINISH();
    return rc;
}

static int create_enc_key_aes_256(TpmRsaKey const *parent_key)
{
    int rc;
    Create_In createIn;
    Create_Out createOut;

    /* Create a symmetric key */
    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent_key->handle;
    createIn.inSensitive.sensitive.userAuth.size = 0;

    createIn.inPublic.publicArea.type = TPM_ALG_SYMCIPHER;
    createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA | TPMA_OBJECT_decrypt | TPMA_OBJECT_sign);
    createIn.inPublic.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
    createIn.inPublic.publicArea.parameters.symDetail.sym.keyBits.aes = MAX_AES_KEY_BITS;
    createIn.inPublic.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_CTR;

    // We dont do anything with the key, we just measure its creation time
    MEASURE_START(TPM_CC_CREATE);
    rc = TPM2_Create(&createIn, &createOut);
    MEASURE_FINISH();
    return rc;
}

static int rsa_encrypt_decrypt(TpmRsaKey const *parent_key, size_t num_loops)
{
    int rc;
    Create_In createIn;
    Create_Out createOut;

    Load_In loadIn;
    Load_Out loadOut;

    uint8_t keyCreationNonce[32];
    fill_random(keyCreationNonce, sizeof(keyCreationNonce));

    /* Create an RSA key for encrypt/decrypt, below the primary key of the NULL hierarchy */
    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent_key->handle;
    
    // We use a zero-size password for accessing the NULL hierarchy
    createIn.inSensitive.sensitive.userAuth.size = 0;
    
    // For the key creation benchmark, we use only 1024 bit keys to speed up the process
    createIn.inPublic.publicArea.type = TPM_ALG_RSA;
    createIn.inPublic.publicArea.unique.rsa.size = STM32TPM_BENCHMARK_RSA_2048_KEY_BITS / 8;
    createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA );
    createIn.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    createIn.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    createIn.inPublic.publicArea.parameters.rsaDetail.keyBits = STM32TPM_BENCHMARK_RSA_2048_KEY_BITS;
    createIn.outsideInfo.size = sizeof(keyCreationNonce)-1;

    // We only create one key using a fixed nonce (we dont measure key creation here)
    XMEMCPY(createIn.outsideInfo.buffer, keyCreationNonce, createIn.outsideInfo.size);

    // We are now using the key to decrypt and encrypt data
    LOG("Creating an RSA-2048 Key for encryption and decryption...\n");
    rc = TPM2_Create(&createIn, &createOut);

    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    /* Load the newly created key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent_key->handle;
    loadIn.inPrivate = createOut.outPrivate;
    loadIn.inPublic = createOut.outPublic;
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    // The hash of the Label is used for OAEP padding, kept constant
    const char label[] = "OAEPLabel";

    LOG("Running encryption/decryption loops...\n");
    for (size_t idx = 0; idx < num_loops; idx++)
    {
        RSA_Encrypt_In rsaEncIn;
        RSA_Encrypt_Out rsaEncOut;

        RSA_Decrypt_In rsaDecIn;
        RSA_Decrypt_Out rsaDecOut;

        // Cleartext message: (keylen[bit] / 8) bytes all holding the current loop index
        TPM2B_PUBLIC_KEY_RSA message;
        generate_unique_message(message.buffer, STM32TPM_BENCHMARK_RSA_2048_OAEP_ENC_BYTES, idx + 1);
        message.size = STM32TPM_BENCHMARK_RSA_2048_OAEP_ENC_BYTES;

        /* RSA Encrypt */
        XMEMSET(&rsaEncIn, 0, sizeof(rsaEncIn));
        rsaEncIn.keyHandle = loadOut.objectHandle;
        rsaEncIn.message = message;
        rsaEncIn.inScheme.scheme = TPM_ALG_OAEP;
        rsaEncIn.inScheme.details.oaep.hashAlg = TPM_ALG_SHA256;
        rsaEncIn.label.size = sizeof(label); /* Null term required */
        XMEMCPY(rsaEncIn.label.buffer, label, rsaEncIn.label.size);
        MEASURE_START(TPM_CC_RSA_ENCRYPT);
        rc = TPM2_RSA_Encrypt(&rsaEncIn, &rsaEncOut);
        MEASURE_FINISH();
        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        /* RSA Decrypt */
        XMEMSET(&rsaDecIn, 0, sizeof(rsaDecIn));
        rsaDecIn.keyHandle = loadOut.objectHandle;
        rsaDecIn.cipherText = rsaEncOut.outData;
        rsaDecIn.inScheme.scheme = TPM_ALG_OAEP;
        rsaDecIn.inScheme.details.oaep.hashAlg = TPM_ALG_SHA256;
        rsaDecIn.label.size = sizeof(label); /* Null term required */
        XMEMCPY(rsaDecIn.label.buffer, label, rsaDecIn.label.size);
        MEASURE_START(TPM_CC_RSA_DECRYPT);
        rc = TPM2_RSA_Decrypt(&rsaDecIn, &rsaDecOut);
        MEASURE_FINISH();
        if (rc != TPM_RC_SUCCESS) 
        {
            return rc;
        }

        if (rsaDecOut.message.size != message.size || 
            XMEMCMP(rsaDecOut.message.buffer, message.buffer, rsaDecOut.message.size))
        {
            // We got something different out than we put in...
            return 1;
        }

        LOG(".");
    }

    LOG("\n");

    FlushContext_In flushIn = {0};
    flushIn.flushHandle = loadOut.objectHandle;
    rc = TPM2_FlushContext(&flushIn);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    return TPM_RC_SUCCESS;
}

static int rsa_sign_validate(TpmRsaKey const *parent_key, size_t num_loops)
{
    int rc;
    Create_In createIn;
    Create_Out createOut;

    Load_In loadIn;
    Load_Out loadOut;

    uint8_t keyCreationNonce[32];
    fill_random(keyCreationNonce, sizeof(keyCreationNonce));

    /* Create an RSA key for encrypt/decrypt, below the primary key of the NULL hierarchy */
    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent_key->handle;
    
    // We use a zero-size password for accessing the NULL hierarchy
    createIn.inSensitive.sensitive.userAuth.size = 0;
    
    // For the key creation benchmark, we use only 1024 bit keys to speed up the process
    createIn.inPublic.publicArea.type = TPM_ALG_RSA;
    createIn.inPublic.publicArea.unique.rsa.size = STM32TPM_BENCHMARK_RSA_2048_KEY_BITS / 8;
    createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        /*TPMA_OBJECT_decrypt |*/ TPMA_OBJECT_sign | TPMA_OBJECT_noDA );
    createIn.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    createIn.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
    createIn.inPublic.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.parameters.rsaDetail.keyBits = STM32TPM_BENCHMARK_RSA_2048_KEY_BITS;
    createIn.outsideInfo.size = sizeof(keyCreationNonce)-1;

    // We only create one key using a fixed nonce (we dont measure key creation here)
    XMEMCPY(createIn.outsideInfo.buffer, keyCreationNonce, createIn.outsideInfo.size);

    // We are now using the key to decrypt and encrypt data
    LOG("Creating an RSA-2048 Key for signing and validation...\n");
    rc = TPM2_Create(&createIn, &createOut);

    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    /* Load the newly created key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent_key->handle;
    loadIn.inPrivate = createOut.outPrivate;
    loadIn.inPublic = createOut.outPublic;
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    LOG("Running signing/verification loops...\n");
    for (size_t idx = 0; idx < num_loops; idx++)
    {
        Sign_In signIn;
        Sign_Out signOut;

        VerifySignature_In verifySignIn;
        VerifySignature_Out verifySignOut;

        XMEMSET(&signIn, 0, sizeof(signIn));
        signIn.keyHandle = loadOut.objectHandle;
        // Digest to sign: the length of the digest match the used hash digest length
        generate_unique_message(signIn.digest.buffer, TPM_SHA256_DIGEST_SIZE, idx + 1);
        signIn.digest.size = TPM_SHA256_DIGEST_SIZE;
        signIn.inScheme.scheme = TPM_ALG_RSASSA;
        signIn.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
        signIn.validation.tag = TPM_ST_HASHCHECK;
        signIn.validation.hierarchy = TPM_RH_NULL;

        MEASURE_START(TPM_CC_SIGN);
        rc = TPM2_Sign(&signIn, &signOut);
        MEASURE_FINISH();

        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        // Verify signature
        XMEMSET(&verifySignIn, 0, sizeof(verifySignIn));
        verifySignIn.keyHandle = loadOut.objectHandle;
        verifySignIn.digest.size = signIn.digest.size;
        XMEMCPY(verifySignIn.digest.buffer, signIn.digest.buffer, verifySignIn.digest.size);
        verifySignIn.signature = signOut.signature;
        
        MEASURE_START(TPM_CC_VERIFYSIGNATURE);
        rc = TPM2_VerifySignature(&verifySignIn, &verifySignOut);
        MEASURE_FINISH();

        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        LOG(".");
    }

    LOG("\n");

    FlushContext_In flushIn = {0};
    flushIn.flushHandle = loadOut.objectHandle;
    rc = TPM2_FlushContext(&flushIn);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    return TPM_RC_SUCCESS;
}

static int ecc_sign_validate(TpmRsaKey const *parent_key, size_t num_loops)
{
    int rc;
    Create_In createIn;
    Create_Out createOut;

    Load_In loadIn;
    Load_Out loadOut;

    /* Create an ECC key for ECDH */
    /* Create an ECC key for signing/validation, below the primary key of the NULL hierarchy */
    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent_key->handle;
    
    // We use a zero-size password for accessing the NULL hierarchy
    createIn.inSensitive.sensitive.userAuth.size = 0;
    createIn.inPublic.publicArea.type = TPM_ALG_ECC;
    createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    createIn.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    createIn.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
    createIn.inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    createIn.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

    LOG("Creating an ECC P-256 Key for signing and validation...\n");
    rc = TPM2_Create(&createIn, &createOut);

    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    /* Load the newly created key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent_key->handle;
    loadIn.inPrivate = createOut.outPrivate;
    loadIn.inPublic = createOut.outPublic;
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    LOG("Running signing/verification loops...\n");
    for (size_t idx = 0; idx < num_loops; idx++)
    {
        Sign_In signIn;
        Sign_Out signOut;

        VerifySignature_In verifySignIn;
        VerifySignature_Out verifySignOut;

        XMEMSET(&signIn, 0, sizeof(signIn));
        signIn.keyHandle = loadOut.objectHandle;
        // Digest to sign: the length of the digest match the used hash digest length
        generate_unique_message(signIn.digest.buffer, TPM_SHA256_DIGEST_SIZE, idx + 1);
        signIn.digest.size = TPM_SHA256_DIGEST_SIZE;
        signIn.inScheme.scheme = TPM_ALG_ECDSA;
        signIn.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
        signIn.validation.tag = TPM_ST_HASHCHECK;
        signIn.validation.hierarchy = TPM_RH_NULL;
        
        MEASURE_START(TPM_CC_SIGN);
        rc = TPM2_Sign(&signIn, &signOut);
        MEASURE_FINISH();
        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        // Verify signature
        XMEMSET(&verifySignIn, 0, sizeof(verifySignIn));
        verifySignIn.keyHandle = loadOut.objectHandle;
        verifySignIn.digest.size = signIn.digest.size;
        XMEMCPY(verifySignIn.digest.buffer, signIn.digest.buffer, verifySignIn.digest.size);
        verifySignIn.signature = signOut.signature;
        MEASURE_START(TPM_CC_VERIFYSIGNATURE);
        rc = TPM2_VerifySignature(&verifySignIn, &verifySignOut);
        MEASURE_FINISH();

        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        LOG(".");
    }

    LOG("\n");

    FlushContext_In flushIn = {0};
    flushIn.flushHandle = loadOut.objectHandle;
    rc = TPM2_FlushContext(&flushIn);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    return TPM_RC_SUCCESS;
}

static int aes_encrypt_decrypt(TpmRsaKey const *parent_key, size_t num_loops)
{
    int rc;
    Create_In createIn;
    Create_Out createOut;

    Load_In loadIn;
    Load_Out loadOut;

    LOG("Creating an AES-256 key...\n");
    /* Create an AES-256 key for encrypt/decrypt, below the primary key of the NULL hierarchy */
    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent_key->handle;
    
    // We use a zero-size password for accessing the NULL hierarchy
    createIn.inSensitive.sensitive.userAuth.size = 0;
    
    createIn.inPublic.publicArea.type = TPM_ALG_SYMCIPHER;
    createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA | TPMA_OBJECT_decrypt | TPMA_OBJECT_sign);
    createIn.inPublic.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
    createIn.inPublic.publicArea.parameters.symDetail.sym.keyBits.aes = MAX_AES_KEY_BITS;
    createIn.inPublic.publicArea.parameters.symDetail.sym.mode.aes = TPM_ALG_CTR;

    // We are now using the key to decrypt and encrypt data
    rc = TPM2_Create(&createIn, &createOut);

    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    /* Load the newly created key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent_key->handle;
    loadIn.inPrivate = createOut.outPrivate;
    loadIn.inPublic = createOut.outPublic;
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    LOG("Running encryption/decryption loops...\n");
    for (size_t idx = 0; idx < num_loops; idx++)
    {
        EncryptDecrypt2_In encDecIn, encDecIn2;
        EncryptDecrypt2_Out encDecOut;

        /* AES Encrypt */
        XMEMSET(&encDecIn, 0, sizeof(encDecIn));
        encDecIn.keyHandle = loadOut.objectHandle;
        // IV
        encDecIn.ivIn.size = MAX_AES_BLOCK_SIZE_BYTES; /* zeros */
        generate_unique_message(encDecIn.ivIn.buffer, MAX_AES_BLOCK_SIZE_BYTES, idx + 1); 
        // Message to encrypt
        generate_unique_message(encDecIn.inData.buffer, STM32TPM_BENCHMARK_AES_256_ENC_BYTES, idx);
        encDecIn.inData.size = STM32TPM_BENCHMARK_AES_256_ENC_BYTES;
        encDecIn.decrypt = NO;
        encDecIn.mode = TPM_ALG_CTR;

        MEASURE_START(TPM_CC_ENCRYPTDECRYPT2);
        rc = TPM2_EncryptDecrypt2(&encDecIn, &encDecOut);
        MEASURE_FINISH();

        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        /* AES Decrypt */
        XMEMSET(&encDecIn2, 0, sizeof(encDecIn2));
        encDecIn2.keyHandle = loadOut.objectHandle;
        // IV, use the same as for the encryption
        encDecIn2.ivIn.size = MAX_AES_BLOCK_SIZE_BYTES;
        XMEMCPY(encDecIn2.ivIn.buffer, encDecIn.ivIn.buffer, encDecIn2.ivIn.size);
        encDecIn2.inData.size = encDecOut.outData.size;
        XMEMCPY(encDecIn2.inData.buffer, encDecOut.outData.buffer, encDecIn2.inData.size);
        encDecIn2.decrypt = YES;
        encDecIn2.mode = TPM_ALG_CTR;
        
        MEASURE_START(TPM_CC_ENCRYPTDECRYPT2);
        rc = TPM2_EncryptDecrypt2(&encDecIn2, &encDecOut);
        MEASURE_FINISH();

        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        if (encDecOut.outData.size != encDecIn.inData.size || 
            XMEMCMP(encDecOut.outData.buffer, encDecIn.inData.buffer, encDecOut.outData.size))
        {
            // We got something different out than we put in...
            return 1;
        }

        LOG(".");
    }

    LOG("\n");

    FlushContext_In flushIn = {0};
    flushIn.flushHandle = loadOut.objectHandle;
    rc = TPM2_FlushContext(&flushIn);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    return TPM_RC_SUCCESS;
}

static int aes_hmac(TpmRsaKey const *parent_key, size_t num_loops)
{
    int rc;
    Create_In createIn;
    Create_Out createOut;

    Load_In loadIn;
    Load_Out loadOut;

    LOG("Creating an AES-256 key...\n");
    /* Create an AES-256 key for HMAC, below the primary key of the NULL hierarchy */
    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent_key->handle;
    
    // We use a zero-size password for accessing the NULL hierarchy
    createIn.inSensitive.sensitive.userAuth.size = 0;
    
    createIn.inPublic.publicArea.type = TPM_ALG_KEYEDHASH;
    createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_noDA | /*TPMA_OBJECT_decrypt |*/ TPMA_OBJECT_sign);
    createIn.inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC; // TPM_ALG_AES;
    createIn.inPublic.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA256;

    // We are now using the key to decrypt and encrypt data
    rc = TPM2_Create(&createIn, &createOut);

    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    /* Load the newly created key */
    XMEMSET(&loadIn, 0, sizeof(loadIn));
    loadIn.parentHandle = parent_key->handle;
    loadIn.inPrivate = createOut.outPrivate;
    loadIn.inPublic = createOut.outPublic;
    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    LOG("Running signing/verification loops...\n");
    for (size_t idx = 0; idx < num_loops; idx++)
    {
        HMAC_In hmacIn;
        HMAC_Out hmacOut;

        XMEMSET(&hmacIn, 0, sizeof(hmacIn));
        hmacIn.handle = loadOut.objectHandle;
        generate_unique_message(hmacIn.buffer.buffer, STM32TPM_BENCHMARK_AES_256_HMAC_BYTES, idx); 
        hmacIn.buffer.size = STM32TPM_BENCHMARK_AES_256_HMAC_BYTES;
        hmacIn.hashAlg = TPM_ALG_SHA256;
        
        MEASURE_START(TPM_CC_HMAC);
        rc = TPM2_HMAC(&hmacIn, &hmacOut);
        MEASURE_FINISH();
        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        LOG(".");
    }

    LOG("\n");

    FlushContext_In flushIn = {0};
    flushIn.flushHandle = loadOut.objectHandle;
    rc = TPM2_FlushContext(&flushIn);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    return TPM_RC_SUCCESS;
}

static int create_storage_key(TpmRsaKey const *parent_key,
                              TpmRsaKey *storage_key)
{
    int rc;
    Create_In createIn = {0};
    Create_Out createOut = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};

    createIn.parentHandle = parent_key->handle;
    createIn.inSensitive.sensitive.userAuth.size = 0;

    createIn.inPublic.publicArea.type = TPM_ALG_RSA;
    createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.objectAttributes =
        TPMA_OBJECT_fixedTPM |
        TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin |
        TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted |
        TPMA_OBJECT_decrypt |
        TPMA_OBJECT_noDA;

    createIn.inPublic.publicArea.parameters.rsaDetail.keyBits = STM32TPM_BENCHMARK_RSA_2048_KEY_BITS;
    createIn.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    createIn.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    createIn.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    createIn.inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    createIn.inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;

    rc = TPM2_Create(&createIn, &createOut);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    loadIn.parentHandle = parent_key->handle;
    loadIn.inPrivate = createOut.outPrivate;
    loadIn.inPublic = createOut.outPublic;

    rc = TPM2_Load(&loadIn, &loadOut);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    storage_key->handle = loadOut.objectHandle;
    storage_key->auth = createIn.inSensitive.sensitive.userAuth;
    storage_key->priv = createOut.outPrivate;
    storage_key->pub = createOut.outPublic;
    storage_key->name = loadOut.name;
    storage_key->symmetric = createIn.inPublic.publicArea.parameters.rsaDetail.symmetric;

    return TPM_RC_SUCCESS;
}

static int seal_unseal(TpmRsaKey const *parent_key, size_t num_loops)
{
    TpmRsaKey storage_key;
    LOG("Creating RSA-2048 Storage Key for sealing/unsealing...\n");
    int rc = create_storage_key(parent_key, &storage_key);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    LOG("Running sealing/unsealing loops...\n");
    for (size_t idx = 0; idx < num_loops; idx++)
    {
        Create_In createIn = {0};
        Create_Out createOut = {0};
        Load_In loadIn = {0};
        Load_Out loadOut = {0};
        Unseal_In unsealIn = {0};
        Unseal_Out unsealOut = {0};
        FlushContext_In flushIn = {0};

        /* Create a sealed object under an existing parent/storage key. */
        createIn.parentHandle = storage_key.handle;
        createIn.inSensitive.sensitive.userAuth.size = 0;  /* or set an object auth value */
        createIn.inSensitive.sensitive.data.size = STM32TPM_BENCHMARK_RSA_2048_SEAL_BYTES;
        generate_unique_message(createIn.inSensitive.sensitive.data.buffer, STM32TPM_BENCHMARK_RSA_2048_SEAL_BYTES, idx);

        createIn.inPublic.publicArea.type = TPM_ALG_KEYEDHASH;
        createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
        createIn.inPublic.publicArea.objectAttributes =
            TPMA_OBJECT_fixedTPM |
            TPMA_OBJECT_fixedParent |
            TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_noDA;

        createIn.inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme =
            TPM_ALG_NULL;

        MEASURE_START(TPM_CC_CREATE);
        rc = TPM2_Create(&createIn, &createOut);
        MEASURE_FINISH();
        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        /* Load the object before unsealing it. */
        loadIn.parentHandle = storage_key.handle;
        loadIn.inPrivate = createOut.outPrivate;
        loadIn.inPublic = createOut.outPublic;
        rc = TPM2_Load(&loadIn, &loadOut);
        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        /* Unseal using the loaded object's handle. */
        unsealIn.itemHandle = loadOut.objectHandle;
        MEASURE_START(TPM_CC_UNSEAL);
        rc = TPM2_Unseal(&unsealIn, &unsealOut);
        MEASURE_FINISH();
        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        /* Verify that the unsealed data and the original one match */
        if ((unsealOut.outData.size != createIn.inSensitive.sensitive.data.size) ||
            (memcmp(unsealOut.outData.buffer, createIn.inSensitive.sensitive.data.buffer, unsealOut.outData.size) != 0))
        {
            /* unsealing didnt get us what we originally sealed */
            return 1;
        }

        /* Remove the object again */
        flushIn.flushHandle = loadOut.objectHandle;
        rc = TPM2_FlushContext(&flushIn);
        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        LOG(".");
    }

    LOG("\n");
    
    return TPM_RC_SUCCESS;
}

static int hashing(char const *hashData, size_t hashDataSize)
{
    int rc;
    TPM_HANDLE handle = TPM_RH_NULL;
    HashSequenceStart_In hashSeqStartIn;
    HashSequenceStart_Out hashSeqStartOut;

    SequenceUpdate_In seqUpdateIn;

    SequenceComplete_In seqCompIn;
    SequenceComplete_Out seqCompOut;
    
    /* Hashing */
    XMEMSET(&hashSeqStartIn, 0, sizeof(hashSeqStartIn));
    hashSeqStartIn.auth.size = 0;
    hashSeqStartIn.hashAlg = TPM_ALG_SHA256;
    MEASURE_START(TPM_CC_HASHSEQUENCESTART);
    rc = TPM2_HashSequenceStart(&hashSeqStartIn, &hashSeqStartOut);
    MEASURE_FINISH();

    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }
    
    handle = hashSeqStartOut.sequenceHandle;

    XMEMSET(&seqUpdateIn, 0, sizeof(seqUpdateIn));
    seqUpdateIn.sequenceHandle = handle;
    seqUpdateIn.buffer.size = hashDataSize;
    XMEMCPY(seqUpdateIn.buffer.buffer, hashData,
        seqUpdateIn.buffer.size);
    MEASURE_START(TPM_CC_SEQUENCEUPDATE);
    rc = TPM2_SequenceUpdate(&seqUpdateIn);
    MEASURE_FINISH();

    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    XMEMSET(&seqCompIn, 0, sizeof(seqCompIn));
    seqCompIn.sequenceHandle = handle;
    seqCompIn.hierarchy = TPM_RH_NULL;
    MEASURE_START(TPM_CC_SEQUENCECOMPLETE);
    rc = TPM2_SequenceComplete(&seqCompIn, &seqCompOut);
    MEASURE_FINISH();

    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    /* Should not really happen */
    if (seqCompOut.result.size != TPM_SHA256_DIGEST_SIZE)
    {
        return 1;
    }

    return TPM_RC_SUCCESS;
}

static int startup_tpm()
{
    Startup_In startup;
    XMEMSET(&startup, 0, sizeof(startup));
    startup.startupType = TPM_SU_CLEAR;
    MEASURE_START(TPM_CC_STARTUP);
    int rc = TPM2_Startup(&startup);
    MEASURE_FINISH();

    /* TPM_RC_INITIALIZE = Already started */
    if (rc != TPM_RC_SUCCESS && rc != TPM_RC_INITIALIZE) 
    {
        return rc;
    }

    return TPM_RC_SUCCESS;
}

#if 0
static TPM_RC print_supported_command_codes(void)
{
    GetCapability_In capIn;
    GetCapability_Out capOut;
    TPM_RC rc;
    UINT32 nextProperty = 0;
    UINT32 i;
    int hasEncryptDecrypt = 0;
    int hasEncryptDecrypt2 = 0;

    printf("TPM-supported command codes:\n");

    do {
        UINT32 lastCommandCode = 0;

        XMEMSET(&capIn, 0, sizeof(capIn));
        XMEMSET(&capOut, 0, sizeof(capOut));

        capIn.capability = TPM_CAP_COMMANDS;
        capIn.property = nextProperty;
        capIn.propertyCount = 64;

        rc = TPM2_GetCapability(&capIn, &capOut);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_GetCapability failed 0x%x: %s\n",
                   (unsigned int)rc, TPM2_GetRCString(rc));
            return rc;
        }

        for (i = 0; i < capOut.capabilityData.data.command.count; i++) {
            TPMA_CC attributes =
                capOut.capabilityData.data.command.commandAttributes[i];

            /* TPMA_CC contains the command index and vendor-command bit. */
            UINT32 commandCode =
                ((UINT32)attributes & 0x0000FFFFU) |
                ((UINT32)attributes & (UINT32)TPMA_CC_V);

            printf("  0x%08x\n", (unsigned int)commandCode);
            lastCommandCode = commandCode;

            if (commandCode == (UINT32)TPM_CC_EncryptDecrypt) {
                hasEncryptDecrypt = 1;
            }
            if (commandCode == (UINT32)TPM_CC_EncryptDecrypt2) {
                hasEncryptDecrypt2 = 1;
            }
        }

        if (capOut.moreData) {
            if (capOut.capabilityData.data.command.count == 0) {
                fprintf(stderr, "TPM returned more data but no command codes\n");
                return TPM_RC_FAILURE;
            }
            nextProperty = lastCommandCode + 1U;
        }
    } while (capOut.moreData);

    printf("EncryptDecrypt (0x%08x): %s\n",
           (unsigned int)TPM_CC_EncryptDecrypt,
           hasEncryptDecrypt ? "supported" : "not listed");
    printf("EncryptDecrypt2 (0x%08x): %s\n",
           (unsigned int)TPM_CC_EncryptDecrypt2,
           hasEncryptDecrypt2 ? "supported" : "not listed");

    return TPM_RC_SUCCESS;
}
#endif

int main(int argc, char *argv[])
{
    int rc;
    TPM2_CTX tpm2Ctx;
    size_t rsa_create_key_length = STM32TPM_BENCHMARK_RSA_1024_KEY_BITS; /* default for debug mode */

    if ((argc != 2) || 
        (   
            (strncmp("debug", argv[1], strlen("debug")) != 0) && 
            (strncmp("release", argv[1], strlen("release")) != 0)
        ))
    {
        fprintf(stderr, "Usage %s [debug|release]\n", argv[0]);
        return 1;
    }

    if (strncmp("release", argv[1], strlen("release")) == 0)
    {
        rsa_create_key_length = STM32TPM_BENCHMARK_RSA_2048_KEY_BITS; /* For release mode, we use 2048 bit keys*/
    }

    init_random(); /* for generating nonces */

    LOG("Accessing TPM using wolfTPM library");
    rc = TPM2_Init(&tpm2Ctx, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        fprintf(stderr, "TPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    /* define the password auth for this session */
    /* the password will have zero length (for the NULL hierarchy we work on) */
    XMEMSET(session, 0, sizeof(session));
    session[0].sessionHandle = TPM_RS_PW;
    TPM2_SetSessionAuth(session);
    
    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }
    LOG("TPM2_Startup pass\n");

    /* 
     * this is the primary key of the NULL hierarchy all benchmark keys will
     * be derived from
     */
    TpmRsaKey null_primary_key;
    LOG("Creating primary RSA-2048 NULL Storage Key...\n");
    rc = create_primary_null_rsa_2048(&null_primary_key);

    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Create Primary Key on NULL storage hierarchy failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    // --- SHA-256 ------------------------------------------------------------

    LOG("Benchmarking SHA256\n");
    for (size_t loop = 0; loop < BENCHMARK_NUM_LOOPS; ++loop)
    {
        uint8_t message_buffer[STM32TPM_BENCHMARK_SHA_256_DATA_BYTES];
        generate_unique_message(message_buffer, STM32TPM_BENCHMARK_SHA_256_DATA_BYTES, loop);

        rc = hashing((const char *)message_buffer, STM32TPM_BENCHMARK_SHA_256_DATA_BYTES);
        if (rc != TPM_RC_SUCCESS)
        {
            fprintf(stderr, "Hash benchmark failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            goto exit;        
        }
        LOG(".");
    }
    LOG("\n");
    LOG("Hash benchmark finished successfully.\n");

    // --- RSA key generation --------------------------------------------

    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }    

    if (rsa_create_key_length == STM32TPM_BENCHMARK_RSA_1024_KEY_BITS)
    {
        LOG("Benchmarking RSA 1024 Key generation\n");
    }
    else
    {
        LOG("Benchmarking RSA 2048 Key generation\n");
    }
    for (size_t loop = 0; loop < BENCHMARK_NUM_LOOPS; ++loop)
    {
        rc = create_enc_key_rsa(&null_primary_key, rsa_create_key_length);
        if (rc != TPM_RC_SUCCESS)
        {
            fprintf(stderr, "Create Key failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            goto exit;        
        }
        LOG(".");
    }
    LOG("\n");
    LOG("RSA 1024 key generation finished successfully.\n");

    // --- ECC P-256 key generation -------------------------------------------

    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }

    LOG("Benchmarking ECC NIST P-256 Key generation\n");
    for (size_t loop = 0; loop < BENCHMARK_NUM_LOOPS; ++loop)
    {
        rc = create_key_ecc_nistp_256(&null_primary_key);
        if (rc != TPM_RC_SUCCESS)
        {
            fprintf(stderr, "Create Key failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            break;
        }
        LOG(".");
    }
    LOG("\n");
    LOG("ECC P-256 key generation finished successfully.\n");


    // AES-256 key generation -------------------------------------------------

    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }

    LOG("Benchmarking AES-256 Key generation\n");
    for (size_t loop = 0; loop < BENCHMARK_NUM_LOOPS; ++loop)
    {
        rc = create_enc_key_aes_256(&null_primary_key);
        if (rc != TPM_RC_SUCCESS)
        {
            fprintf(stderr, "Create Key failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            break;
        }
        LOG(".");
    }
    LOG("\n");
    LOG("AES-256 Key generation finished successfully.\n");

    // RSA-2048 encryption/decryption -----------------------------------------

    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }
    LOG("Benchmarking RSA 2048 encryption/decryption\n");

    rc = rsa_encrypt_decrypt(&null_primary_key, BENCHMARK_NUM_LOOPS);
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "RSA 2048 encryption and decryption failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }

    LOG("RSA 2048 encryption and decryption finished successfully.\n");

#if 0
    rc = print_supported_command_codes();
    if (rc != TPM_RC_SUCCESS) {
        goto exit;
    }
#endif

    // AES-256 encryption/decryption -----------------------------------------

    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }
    LOG("Benchmarking AES-256 encryption/decryption\n");

    rc = aes_encrypt_decrypt(&null_primary_key, BENCHMARK_NUM_LOOPS);
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "AES-256 encryption and decryption failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    LOG("AES-256 encryption/decryption finished successfully.\n");

    // --- ECC P-256 sign/validate --------------------------------------------

    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }
    LOG("Benchmarking ECC P-256 signing/validation\n");

    rc = ecc_sign_validate(&null_primary_key, BENCHMARK_NUM_LOOPS);
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "ECC P-256 signing/validation failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    LOG("ECC P-256 signing/validation finished successfully.\n");

    // --- RSA 2048 sign/validate --------------------------------------------

    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }
    LOG("Benchmarking RSA 2048 signing/validation\n");

    rc = rsa_sign_validate(&null_primary_key, BENCHMARK_NUM_LOOPS);
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "RSA 2048 signing/validation failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    LOG("RSA 2048 signing/validation finished successfully.\n");

    // --- AES 256 HMAC -------------------------------------------------------

    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }
    LOG("Benchmarking AES 256 HMAC generation\n");

    rc = aes_hmac(&null_primary_key, BENCHMARK_NUM_LOOPS);
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "AES 256 HMAC generation failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    LOG("AES 256 HMAC generation finished successfully.\n");

    // --- Sealing/Unsealing with RSA 2048 key --------------------------------

    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }

    LOG("Benchmarking Sealing and Unsealing Data\n");
    rc = seal_unseal(&null_primary_key, BENCHMARK_NUM_LOOPS);

    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Sealing/unsealing data failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    LOG("Sealing/unsealing finished successfully.\n");

    LOG("TPM2 Benchmark finished successfully.\n");

exit:
    /* Shutdown */
    Shutdown_In shutdown;
    shutdown.shutdownType = TPM_SU_CLEAR;
    if (TPM2_Shutdown(&shutdown) != TPM_RC_SUCCESS) {
        LOG("TPM2_Shutdown failed\n");
    }

    TPM2_Cleanup(&tpm2Ctx);

    export_measurements();

    return 0;
}
