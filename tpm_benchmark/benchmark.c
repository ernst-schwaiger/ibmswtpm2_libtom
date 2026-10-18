#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <stdio.h>
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_param_enc.h>

#include <examples/native/native_test.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

#define MAX_STM32TPM_RSA_KEY_BITS   (3072U)
#define MAX_STM32TPM_BENCHMARK_RSA_KEY_BITS   (1024U)

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
    // createPriIn.inPublic.publicArea.authPolicy.size =
    //     sizeof(TPM_20_EK_AUTH_POLICY);
    // XMEMCPY(createPriIn.inPublic.publicArea.authPolicy.buffer,
    //     TPM_20_EK_AUTH_POLICY,
    //     createPriIn.inPublic.publicArea.authPolicy.size);
    
    // Ernst: Test whether an empty policy works here
    createPriIn.inPublic.publicArea.authPolicy.size = 0;
    createPriIn.inPublic.publicArea.type = TPM_ALG_RSA;

    /* Ernst: our simulator supports at most 3072bit RSA Keys*/
    //createPriIn.inPublic.publicArea.unique.rsa.size = MAX_RSA_KEY_BITS / 8;
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

int create_enc_key_rsa_2048(TpmRsaKey const *parent_key)
{
    int rc;

    Create_In createIn;
    Create_Out createOut;
    const char keyCreationNonce[] = "RandomServerPickedCreationNonce";

    /* Create an RSA key for encrypt/decrypt */
    XMEMSET(&createIn, 0, sizeof(createIn));
    createIn.parentHandle = parent_key->handle;
    // createIn.inSensitive.sensitive.userAuth.size = sizeof(usageAuth)-1;
    // XMEMCPY(createIn.inSensitive.sensitive.userAuth.buffer, usageAuth,
    //     createIn.inSensitive.sensitive.userAuth.size);

    createIn.inSensitive.sensitive.userAuth.size = 0;
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
    XMEMCPY(createIn.outsideInfo.buffer, keyCreationNonce,
        createIn.outsideInfo.size);
    rc = TPM2_Create(&createIn, &createOut);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }

    // printf("TPM2_Create: New RSA Key: pub %d, priv %d\n",
    //     cmdOut.create.outPublic.size,
    //     cmdOut.create.outPrivate.size);
    // rsaKey.pub = cmdOut.create.outPublic;
    // rsaKey.priv = cmdOut.create.outPrivate;
    /* Keep creation Hash for certifyCreation unit test below */
    // rsaKey.creationHash.size = cmdOut.create.creationHash.size;
    // XMEMCPY(rsaKey.creationHash.buffer, cmdOut.create.creationHash.buffer, rsaKey.creationHash.size);
    // /* Keep creation Ticket for certifyCreation unit test below */
    // XMEMCPY(&rsaKey.creationTicket, &cmdOut.create.creationTicket, sizeof(rsaKey.creationTicket));

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
    hashSeqStartIn.auth.size = sizeof(usageAuth)-1;
    XMEMCPY(hashSeqStartIn.auth.buffer, usageAuth,
        hashSeqStartIn.auth.size);
    hashSeqStartIn.hashAlg = TPM_ALG_SHA256;
    rc = TPM2_HashSequenceStart(&hashSeqStartIn, &hashSeqStartOut);
    if (rc != TPM_RC_SUCCESS)
    {
        return rc;
    }
    
    handle = hashSeqStartOut.sequenceHandle;

    /* set auth for hashing handle */
    session[0].auth.size = sizeof(usageAuth)-1;
    XMEMCPY(session[0].auth.buffer, usageAuth, session[0].auth.size);

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

    /* define the default session auth */
    XMEMSET(session, 0, sizeof(session));
    session[0].sessionHandle = TPM_RS_PW;
    TPM2_SetSessionAuth(session);

    Startup_In startup;
    XMEMSET(&startup, 0, sizeof(startup));
    startup.startupType = TPM_SU_CLEAR;
    rc = TPM2_Startup(&startup);
    if (rc != TPM_RC_SUCCESS &&
        rc != TPM_RC_INITIALIZE /* TPM_RC_INITIALIZE = Already started */ ) {
        printf("TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Startup pass\n");

    /* clear session auth */
    session[0].auth.size = 0;
    XMEMSET(session[0].auth.buffer, 0, sizeof(session[0].auth.buffer));


    for (size_t loop = 0; loop < 100; ++loop)
    {
        rc = hashing(hashInputData, XSTRLEN(hashInputData));
        if (rc != TPM_RC_SUCCESS)
        {
            printf("Hash benchmark failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            break;
        }
    }


    // /* clear session auth */
    // session[0].auth.size = 0;
    // XMEMSET(session[0].auth.buffer, 0, sizeof(session[0].auth.buffer));

    // TpmRsaKey null_primary_key;
    // rc = create_primary_null_rsa_2048(&null_primary_key);

    // if (rc != TPM_RC_SUCCESS)
    // {
    //     printf("Create Primary Key on NULL storage hierarchy failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    //     goto exit;
    // }

    // for (size_t loop = 0; loop < 40; ++loop)
    // {
    //     rc = create_enc_key_rsa_2048(&null_primary_key);
    //     if (rc != TPM_RC_SUCCESS)
    //     {
    //         printf("Create Primary Key failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
    //         break;
    //     }
    // }

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
