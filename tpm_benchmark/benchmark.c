#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <stdio.h>
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_param_enc.h>

#include <examples/native/native_test.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#define MAX_STM32TPM_RSA_KEY_BITS               (3072U)
#define MAX_STM32TPM_BENCHMARK_RSA_KEY_BITS     (1024U)
#define BENCHMARK_NUM_LOOPS                     (5U)

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


const char storagePwd[] = "WolfTPMPassword";
const char usageAuth[] = "ThisIsASecretUsageAuth";
TPM2_AUTH_SESSION session[MAX_SESSION_NUM];

const char* hashTestData =
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

char const *hashInputData = "The quick brown fox jumps over the lazy dog";

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
    createPriIn.inPublic.publicArea.unique.rsa.size = MAX_STM32TPM_BENCHMARK_RSA_KEY_BITS / 8;
    createPriIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createPriIn.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_fixedTPM | TPMA_OBJECT_fixedParent |
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_restricted | TPMA_OBJECT_decrypt);
    createPriIn.inPublic.publicArea.parameters.rsaDetail.keyBits = MAX_STM32TPM_BENCHMARK_RSA_KEY_BITS;
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

static int create_enc_key_rsa_2048(TpmRsaKey const *parent_key)
{
    int rc;
    Create_In createIn;
    Create_Out createOut;
    const char keyCreationNonce[] = "RandomServerPickedCreationNonce";

    /* Create an RSA key for encrypt/decrypt, below the primary key of the NULL hierarchy */
    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent_key->handle;
    
    // We use a zero-size password for accessing the NULL hierarchy
    createIn.inSensitive.sensitive.userAuth.size = 0;
    
    // For the key creation benchmark, we use only 1024 bit keys to speed up the process
    createIn.inPublic.publicArea.type = TPM_ALG_RSA;
    createIn.inPublic.publicArea.unique.rsa.size = MAX_STM32TPM_BENCHMARK_RSA_KEY_BITS / 8;
    createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA );
    createIn.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    createIn.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    createIn.inPublic.publicArea.parameters.rsaDetail.keyBits = MAX_STM32TPM_BENCHMARK_RSA_KEY_BITS;
    createIn.outsideInfo.size = sizeof(keyCreationNonce)-1;

    // FIXME: Randomize the nonce, or use a different one each loop?
    XMEMCPY(createIn.outsideInfo.buffer, keyCreationNonce, createIn.outsideInfo.size);

    // We dont to anthing with the key here; we just measure the time it takes to create it
    rc = TPM2_Create(&createIn, &createOut);
    return rc;
}

static int create_key_ecc_nistp_256(TpmRsaKey const *parent_key)
{
    int rc;
    Create_In createIn;
    Create_Out createOut;
    const char keyCreationNonce[] = "RandomServerPickedCreationNonce";

    /* Create an ECC key for ECDH */
    /* Create an ECC key for encrypt/decrypt, below the primary key of the NULL hierarchy */
    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent_key->handle;
    
    // We use a zero-size password for accessing the NULL hierarchy
    createIn.inSensitive.sensitive.userAuth.size = 0;
    // XMEMCPY(createIn.inSensitive.sensitive.userAuth.buffer, usageAuth,
    //     usageAuthSz);
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
    
    rc = TPM2_Create(&createIn, &createOut);
    return rc;
    // if (is_curve_or_cmd_unsupported(rc, mayBeUnsupported)) {
    //     printf("TPM2_Create ECDH curve 0x%04x not supported, skipping\n",
    //         TPM_ECC_NIST_P256);
    //     rc = 0;
    //     goto done;
    // }


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
    rc = TPM2_HashSequenceStart(&hashSeqStartIn, &hashSeqStartOut);
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
    rc = TPM2_SequenceUpdate(&seqUpdateIn);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    XMEMSET(&seqCompIn, 0, sizeof(seqCompIn));
    seqCompIn.sequenceHandle = handle;
    seqCompIn.hierarchy = TPM_RH_NULL;
    rc = TPM2_SequenceComplete(&seqCompIn, &seqCompOut);
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
    int rc = TPM2_Startup(&startup);
    
    /* TPM_RC_INITIALIZE = Already started */
    if (rc != TPM_RC_SUCCESS && rc != TPM_RC_INITIALIZE) 
    {
        return rc;
    }

    return TPM_RC_SUCCESS;
}

int main(int argc, char *argv[])
{
    int rc;
    TPM2_CTX tpm2Ctx;

    printf("Accessing TPM using wolfTPM library");
    rc = TPM2_Init(&tpm2Ctx, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    printf("TPM2: Caps 0x%08x, Did 0x%04x, Vid 0x%04x, Rid 0x%2x \n",
        tpm2Ctx.caps,
        tpm2Ctx.did_vid >> 16,
        tpm2Ctx.did_vid & 0xFFFF,
        tpm2Ctx.rid);

    /* define the password auth for this session */
    /* the password will have zero length (for the NULL hierarchy we work on) */
    XMEMSET(session, 0, sizeof(session));
    session[0].sessionHandle = TPM_RS_PW;
    TPM2_SetSessionAuth(session);

    
    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        printf("TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }
    printf("TPM2_Startup pass\n");

    printf("Benchmarking SHA256\n");
    for (size_t loop = 0; loop < BENCHMARK_NUM_LOOPS; ++loop)
    {
        rc = hashing(hashInputData, XSTRLEN(hashInputData));
        if (rc != TPM_RC_SUCCESS)
        {
            printf("Hash benchmark failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            break;
        }
        printf(".");
        fflush(stdout);
    }
    printf("\n");

    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        printf("TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }    

    TpmRsaKey null_primary_key;
    rc = create_primary_null_rsa_2048(&null_primary_key);

    if (rc != TPM_RC_SUCCESS)
    {
        printf("Create Primary Key on NULL storage hierarchy failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    printf("Benchmarking RSA 1024 Key generation\n");
    for (size_t loop = 0; loop < BENCHMARK_NUM_LOOPS; ++loop)
    {
        rc = create_enc_key_rsa_2048(&null_primary_key);
        if (rc != TPM_RC_SUCCESS)
        {
            printf("Create Key failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            break;
        }
        printf(".");
        fflush(stdout);
    }
    printf("\n");

    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        printf("TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }

    printf("Benchmarking ECC NIST P-256 Key generation\n");
    for (size_t loop = 0; loop < BENCHMARK_NUM_LOOPS; ++loop)
    {
        rc = create_key_ecc_nistp_256(&null_primary_key);
        if (rc != TPM_RC_SUCCESS)
        {
            printf("Create Key failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            break;
        }
        printf(".");
        fflush(stdout);
    }
    printf("\n");


    printf("TPM2 Benchmark finished successfully.\n");

exit:
    /* Shutdown */
    Shutdown_In shutdown;
    shutdown.shutdownType = TPM_SU_CLEAR;
    if (TPM2_Shutdown(&shutdown) != TPM_RC_SUCCESS) {
        printf("TPM2_Shutdown failed\n");
    }

    TPM2_Cleanup(&tpm2Ctx);

    return 0;
}
