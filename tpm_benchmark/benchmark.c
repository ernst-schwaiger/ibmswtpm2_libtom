#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <stdio.h>
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_param_enc.h>

#include <examples/native/native_test.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>

const char storagePwd[] = "WolfTPMPassword";
const char usageAuth[] = "ThisIsASecretUsageAuth";
TPM2_AUTH_SESSION session[MAX_SESSION_NUM];

void hashing()
{
    const char* hashTestData =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    const char* hashTestDig =
        "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60"
        "\x39\xA3\x3C\xE4\x59\x64\xFF\x21\x67\xF6\xEC\xED\xD4\x19\xDB"
        "\x06\xC1";

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
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_HashSequenceStart failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        return;
    }
    
    handle = hashSeqStartOut.sequenceHandle;
    printf("TPM2_HashSequenceStart: sequenceHandle 0x%x\n", (word32)handle);

    /* set auth for hashing handle */
    session[0].auth.size = sizeof(usageAuth)-1;
    XMEMCPY(session[0].auth.buffer, usageAuth, session[0].auth.size);

    XMEMSET(&seqUpdateIn, 0, sizeof(seqUpdateIn));
    seqUpdateIn.sequenceHandle = handle;
    seqUpdateIn.buffer.size = XSTRLEN(hashTestData);
    XMEMCPY(seqUpdateIn.buffer.buffer, hashTestData,
        seqUpdateIn.buffer.size);
    rc = TPM2_SequenceUpdate(&seqUpdateIn);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_SequenceUpdate failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        return;
    }

    XMEMSET(&seqCompIn, 0, sizeof(seqCompIn));
    seqCompIn.sequenceHandle = handle;
    seqCompIn.hierarchy = TPM_RH_NULL;
    rc = TPM2_SequenceComplete(&seqCompIn, &seqCompOut);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_SequenceComplete failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        return;
    }
    if (seqCompOut.result.size != TPM_SHA256_DIGEST_SIZE ||
        XMEMCMP(seqCompOut.result.buffer, hashTestDig,
                                                TPM_SHA256_DIGEST_SIZE) != 0) {
        printf("Hash SHA256 test failed, result not as expected!\n");
        return;
    }
    printf("Hash SHA256 test success\n");
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

    hashing();

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
