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
#define STM32TPM_BENCHMARK_RSA_1024_KEY_BITS    (1024U)
#define STM32TPM_BENCHMARK_RSA_2048_KEY_BITS    (2048U)

#define BENCHMARK_NUM_LOOPS                     (40U)

#define LOG(s) do { fprintf(stdout, s); fflush(stdout); } while(0)

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

static int create_enc_key_rsa_1024(TpmRsaKey const *parent_key)
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
    createIn.inPublic.publicArea.unique.rsa.size = STM32TPM_BENCHMARK_RSA_1024_KEY_BITS / 8;
    createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.publicArea.objectAttributes = (
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA );
    createIn.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    createIn.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    createIn.inPublic.publicArea.parameters.rsaDetail.keyBits = STM32TPM_BENCHMARK_RSA_1024_KEY_BITS;
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
    rc = TPM2_Create(&createIn, &createOut);
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
    rc = TPM2_Create(&createIn, &createOut);
    return rc;
}

static int rsa_encrypt_decrypt(TpmRsaKey const *parent_key, size_t num_loops)
{
    int rc;
    Create_In createIn;
    Create_Out createOut;

    Load_In loadIn;
    Load_Out loadOut;

    const char keyCreationNonce[] = "RandomServerPickedCreationNonce";
    LOG("Creating a 2048 bit RSA key pair...\n");

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

    // FIXME: Configure Label and Cleartext properly
    const char label[] = "ThisIsMyLabel";

    LOG("Running encryption/decryption loops...\n");
    for (size_t idx = 0; idx < num_loops; idx++)
    {
        RSA_Encrypt_In rsaEncIn;
        RSA_Encrypt_Out rsaEncOut;

        RSA_Decrypt_In rsaDecIn;
        RSA_Decrypt_Out rsaDecOut;

        // Cleartext message: (keylen[bit] / 8) bytes all holding the current loop index
        TPM2B_PUBLIC_KEY_RSA message;
        XMEMSET(message.buffer, idx % 256, TPM_SHA256_DIGEST_SIZE);
        message.size = TPM_SHA256_DIGEST_SIZE;

        /* RSA Encrypt */
        XMEMSET(&rsaEncIn, 0, sizeof(rsaEncIn));
        rsaEncIn.keyHandle = loadOut.objectHandle;
        rsaEncIn.message = message;
        rsaEncIn.inScheme.scheme = TPM_ALG_OAEP;
        rsaEncIn.inScheme.details.oaep.hashAlg = TPM_ALG_SHA256;
        rsaEncIn.label.size = sizeof(label); /* Null term required */
        XMEMCPY(rsaEncIn.label.buffer, label, rsaEncIn.label.size);
        rc = TPM2_RSA_Encrypt(&rsaEncIn, &rsaEncOut);
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
        rc = TPM2_RSA_Decrypt(&rsaDecIn, &rsaDecOut);
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

    const char keyCreationNonce[] = "RandomServerPickedCreationNonce";

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

        // Message to sign : (keylen[bit] / 8) bytes all holding the current loop index
        TPM2B_PUBLIC_KEY_RSA message;
        XMEMSET(message.buffer, idx % 256, TPM_SHA256_DIGEST_SIZE);
        message.size = TPM_SHA256_DIGEST_SIZE;

        XMEMSET(&signIn, 0, sizeof(signIn));
        signIn.keyHandle = loadOut.objectHandle;
        signIn.digest.size = message.size;
        XMEMCPY(signIn.digest.buffer, message.buffer, message.size);
        signIn.inScheme.scheme = TPM_ALG_RSASSA;
        signIn.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
        signIn.validation.tag = TPM_ST_HASHCHECK;
        signIn.validation.hierarchy = TPM_RH_NULL;

        rc = TPM2_Sign(&signIn, &signOut);
        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        // Verify signature
        XMEMSET(&verifySignIn, 0, sizeof(verifySignIn));
        verifySignIn.keyHandle = loadOut.objectHandle;
        verifySignIn.digest.size = message.size;
        XMEMCPY(verifySignIn.digest.buffer, message.buffer, message.size);
        verifySignIn.signature = signOut.signature;
        rc = TPM2_VerifySignature(&verifySignIn, &verifySignOut);

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
    /* Create an ECC key for encrypt/decrypt, below the primary key of the NULL hierarchy */
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

        // Message to sign : (keylen[bit] / 8) bytes all holding the current loop index
        TPM2B_PUBLIC_KEY_RSA message;
        XMEMSET(message.buffer, idx % 256, TPM_SHA256_DIGEST_SIZE);
        message.size = TPM_SHA256_DIGEST_SIZE;

        XMEMSET(&signIn, 0, sizeof(signIn));
        signIn.keyHandle = loadOut.objectHandle;
        signIn.digest.size = message.size;
        XMEMCPY(signIn.digest.buffer, message.buffer, message.size);
        signIn.inScheme.scheme = TPM_ALG_ECDSA;
        signIn.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
        signIn.validation.tag = TPM_ST_HASHCHECK;
        signIn.validation.hierarchy = TPM_RH_NULL;

        rc = TPM2_Sign(&signIn, &signOut);
        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        // Verify signature
        XMEMSET(&verifySignIn, 0, sizeof(verifySignIn));
        verifySignIn.keyHandle = loadOut.objectHandle;
        verifySignIn.digest.size = message.size;
        XMEMCPY(verifySignIn.digest.buffer, message.buffer, message.size);
        verifySignIn.signature = signOut.signature;
        rc = TPM2_VerifySignature(&verifySignIn, &verifySignOut);

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
        EncryptDecrypt2_In encDecIn;
        EncryptDecrypt2_Out encDecOut;

        // Cleartext message: (keylen[bit] / 8) bytes all holding the current loop index
        TPM2B_PUBLIC_KEY_RSA message;
        // FIXME: Larger Payload for encrypt/decrypt
        XMEMSET(message.buffer, idx % 256, TPM_SHA256_DIGEST_SIZE);
        message.size = TPM_SHA256_DIGEST_SIZE;

        /* AES Encrypt */
        XMEMSET(&encDecIn, 0, sizeof(encDecIn));
        encDecIn.keyHandle = loadOut.objectHandle;
        // FIXME: Provide a non-zero IV (check: do we need an IV in counter mode, anyways?)
        encDecIn.ivIn.size = MAX_AES_BLOCK_SIZE_BYTES; /* zeros */
        encDecIn.inData.size = message.size;
        XMEMCPY(encDecIn.inData.buffer, message.buffer, encDecIn.inData.size);
        encDecIn.decrypt = NO;
        encDecIn.mode = TPM_ALG_CTR;

        rc = TPM2_EncryptDecrypt2(&encDecIn, &encDecOut);
        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        /* AES Decrypt */
        XMEMSET(&encDecIn, 0, sizeof(encDecIn));
        encDecIn.keyHandle = loadOut.objectHandle;
        // FIXME: Same as above: IV in counter mode?
        encDecIn.ivIn.size = MAX_AES_BLOCK_SIZE_BYTES; /* zeros */
        encDecIn.inData.size = message.size;
        XMEMCPY(encDecIn.inData.buffer, encDecOut.outData.buffer, encDecOut.outData.size);
        encDecIn.decrypt = YES;
        encDecIn.mode = TPM_ALG_CTR;

        rc = TPM2_EncryptDecrypt2(&encDecIn, &encDecOut);
        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

        if (encDecOut.outData.size != TPM_SHA256_DIGEST_SIZE || 
            XMEMCMP(encDecOut.outData.buffer, message.buffer, encDecOut.outData.size))
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

        // Message to sign : (keylen[bit] / 8) bytes all holding the current loop index
        TPM2B_PUBLIC_KEY_RSA message;
        XMEMSET(message.buffer, idx % 256, TPM_SHA256_DIGEST_SIZE);
        message.size = TPM_SHA256_DIGEST_SIZE;

        XMEMSET(&hmacIn, 0, sizeof(hmacIn));
        hmacIn.handle = loadOut.objectHandle;
        XMEMCPY(hmacIn.buffer.buffer, message.buffer, message.size);
        hmacIn.buffer.size = message.size;
        hmacIn.hashAlg = TPM_ALG_SHA256;

        rc = TPM2_HMAC(&hmacIn, &hmacOut);
        if (rc != TPM_RC_SUCCESS)
        {
            return rc;
        }

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
    uint8_t payload_buffer[32];

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

        memset(payload_buffer, 0x0, sizeof(payload_buffer));
        sprintf((char *)payload_buffer, "My secret message: %ld", idx);

        /* Create a sealed object under an existing parent/storage key. */
        createIn.parentHandle = storage_key.handle;
        createIn.inSensitive.sensitive.userAuth.size = 0;  /* or set an object auth value */
        createIn.inSensitive.sensitive.data.size = sizeof(payload_buffer);
        XMEMCPY(createIn.inSensitive.sensitive.data.buffer, payload_buffer, createIn.inSensitive.sensitive.data.size);

        createIn.inPublic.publicArea.type = TPM_ALG_KEYEDHASH;
        createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
        createIn.inPublic.publicArea.objectAttributes =
            TPMA_OBJECT_fixedTPM |
            TPMA_OBJECT_fixedParent |
            TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_noDA;

        createIn.inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme =
            TPM_ALG_NULL;

        rc = TPM2_Create(&createIn, &createOut);
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
        rc = TPM2_Unseal(&unsealIn, &unsealOut);
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
        rc = hashing(hashInputData, XSTRLEN(hashInputData));
        if (rc != TPM_RC_SUCCESS)
        {
            fprintf(stderr, "Hash benchmark failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            goto exit;        
        }
        LOG(".");
    }
    LOG("\n");
    LOG("Hash benchmark finished successfully.\n");

    // --- RSA 1024 key generation --------------------------------------------

    rc = startup_tpm();
    if (rc != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "TPM2_Startup failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;        
    }    

    LOG("Benchmarking RSA 1024 Key generation\n");
    for (size_t loop = 0; loop < BENCHMARK_NUM_LOOPS; ++loop)
    {
        rc = create_enc_key_rsa_1024(&null_primary_key);
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

    return 0;
}
