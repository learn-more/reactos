/*
 * Copyright 2009 Henri Verbeet for CodeWeavers
 * Copyright 2018 Hans Leidekker for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include "config.h"
#include "wine/port.h"

#include <stdarg.h>
//#ifdef HAVE_GNUTLS_CIPHER_INIT
//#include <gnutls/gnutls.h>
//#include <gnutls/crypto.h>
//#include <gnutls/abstract.h>
//#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "ntsecapi.h"
#include "bcrypt.h"

#include "bcrypt_internal.h"

#include "wine/debug.h"
#include "wine/heap.h"
#include "wine/library.h"
#include "wine/unicode.h"

WINE_DEFAULT_DEBUG_CHANNEL(bcrypt);
WINE_DECLARE_DEBUG_CHANNEL(winediag);


static ULONG get_block_size( struct algorithm *alg )
{
    ULONG ret = 0, size = sizeof(ret);
    get_alg_property( alg, BCRYPT_BLOCK_LENGTH, (UCHAR *)&ret, sizeof(ret), &size );
    return ret;
}

static mbedtls_cipher_type_t get_mbedtls_cipher(const struct key *key)
{
    switch (key->alg_id)
    {
    case ALG_ID_AES:
        WARN("handle block size\n");
        switch (key->u.s.mode)
        {
        case MODE_ID_GCM:
            if (key->u.s.secret_len == 16) return MBEDTLS_CIPHER_AES_128_GCM;
            if (key->u.s.secret_len == 32) return MBEDTLS_CIPHER_AES_256_GCM;
            break;
        case MODE_ID_ECB: /* can be emulated with CBC + empty IV */
        case MODE_ID_CBC:
            if (key->u.s.secret_len == 16) return MBEDTLS_CIPHER_AES_128_CBC;
            if (key->u.s.secret_len == 24) return MBEDTLS_CIPHER_AES_192_CBC;
            if (key->u.s.secret_len == 32) return MBEDTLS_CIPHER_AES_256_CBC;
            break;
        default:
            break;
        }
        FIXME("aes mode %u with key length %u not supported\n", key->u.s.mode, key->u.s.secret_len);
        return MBEDTLS_CIPHER_NONE;
    default:
        FIXME("algorithm %u not supported\n", key->alg_id);
        return MBEDTLS_CIPHER_NONE;
    }
}

#if 0
static NTSTATUS import_mbedtls_pubkey_ecc(struct key *key)
{
    BCRYPT_ECCKEY_BLOB *ecc_blob;
    mbedtls_ecp_keypair *ecc;
    gnutls_ecc_curve_t curve;
    gnutls_datum_t x, y;
    int ret;

    switch (key->alg_id)
    {
    case ALG_ID_ECDSA_P256: curve = GNUTLS_ECC_CURVE_SECP256R1; break;
    case ALG_ID_ECDSA_P384: curve = GNUTLS_ECC_CURVE_SECP384R1; break;

    default:
        FIXME("Algorithm %d not yet supported\n", key->alg_id);
        return STATUS_NOT_IMPLEMENTED;
    }

    ecc_blob = (BCRYPT_ECCKEY_BLOB *)key->u.a.pubkey;
    ecc = mbedtls_pk_ec(*key->u.a.handle);
    x.data = key->u.a.pubkey + sizeof(*ecc_blob);
    x.size = ecc_blob->cbKey;
    y.data = key->u.a.pubkey + sizeof(*ecc_blob) + ecc_blob->cbKey;
    y.size = ecc_blob->cbKey;

    if ((ret = pgnutls_pubkey_import_ecc_raw(*gnutls_key, curve, &x, &y)))
    {
        pgnutls_perror(ret);
        pgnutls_pubkey_deinit(*gnutls_key);
        return STATUS_INTERNAL_ERROR;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS import_mbedtls_pubkey_rsa(struct key *key)
{
    BCRYPT_RSAKEY_BLOB *rsa_blob;
    mbedtls_rsa_context *rsa;
    int ret;

    rsa_blob = (BCRYPT_RSAKEY_BLOB *)key->u.a.pubkey;
    //e.data = key->u.a.pubkey + sizeof(*rsa_blob);
    //e.size = rsa_blob->cbPublicExp;
    //m.data = key->u.a.pubkey + sizeof(*rsa_blob) + rsa_blob->cbPublicExp;
    //m.size = rsa_blob->cbModulus;
    rsa = mbedtls_pk_parse_key(key->u.a.handle, key->u.a.pubkey, rsa_blob->cbPublicExp+rsa_blob->cbModulus, NULL, 0);
    //memcpy(rsa->N.p, key->u.a.pubkey + sizeof(*rsa_blob) + rsa_blob->cbPublicExp, rsa_blob->cbModulus);
    //memcpy(rsa->E.p, key->u.a.pubkey + sizeof(*rsa_blob), rsa_blob->cbPublicExp);

    return STATUS_SUCCESS;
}
#endif
static NTSTATUS import_mbedtls_pubkey(struct key *key)
{
    __debugbreak();
    switch (key->alg_id)
    {
    //case ALG_ID_ECDSA_P256:
    //case ALG_ID_ECDSA_P384:
    //    return import_mbedtls_pubkey_ecc(key);
    //case ALG_ID_RSA:
    //    return import_mbedtls_pubkey_rsa(key);

    default:
        FIXME("Algorithm %d not yet supported\n", key->alg_id);
        return STATUS_NOT_IMPLEMENTED;
    }
}


NTSTATUS key_set_property( struct key *key, const WCHAR *prop, UCHAR *value, ULONG size, ULONG flags )
{
    if (!strcmpW( prop, BCRYPT_CHAINING_MODE ))
    {
        if (!strncmpW( (WCHAR *)value, BCRYPT_CHAIN_MODE_ECB, size ))
        {
            key->u.s.mode = MODE_ID_ECB;
            return STATUS_SUCCESS;
        }
        else if (!strncmpW( (WCHAR *)value, BCRYPT_CHAIN_MODE_CBC, size ))
        {
            key->u.s.mode = MODE_ID_CBC;
            return STATUS_SUCCESS;
        }
        else if (!strncmpW( (WCHAR *)value, BCRYPT_CHAIN_MODE_GCM, size ))
        {
            key->u.s.mode = MODE_ID_GCM;
            return STATUS_SUCCESS;
        }
        else
        {
            FIXME( "unsupported mode %s\n", debugstr_wn( (WCHAR *)value, size ) );
            return STATUS_NOT_IMPLEMENTED;
        }
    }

    FIXME( "unsupported key property %s\n", debugstr_w(prop) );
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS key_symmetric_init( struct key *key, struct algorithm *alg, const UCHAR *secret, ULONG secret_len )
{
    UCHAR *buffer;
    int ret, key_bitlen;
    const mbedtls_cipher_info_t* info;
    mbedtls_cipher_mode_t mode = MBEDTLS_MODE_NONE;

    switch (alg->id)
    {
    case ALG_ID_AES:
        break;

    default:
        FIXME("algorithm %u not supported\n", alg->id);
        return STATUS_NOT_SUPPORTED;
    }

    switch (alg->mode)
    {
    case MODE_ID_ECB:
        mode = MBEDTLS_MODE_ECB;
        break;

    case MODE_ID_CBC:
        mode = MBEDTLS_MODE_CBC;
        break;

    case MODE_ID_GCM:
        mode = MBEDTLS_MODE_GCM;
        break;

    default:
        FIXME("mode %u not supported\n", alg->mode);
        return STATUS_NOT_SUPPORTED;
    }

    if (!(key->u.s.block_size = get_block_size(alg))) return STATUS_INVALID_PARAMETER;
    if (!(buffer = heap_alloc(secret_len))) return STATUS_NO_MEMORY;
    //if (!(key->u.s.iv = heap_alloc(secret_len))) return STATUS_NO_MEMORY;
    //if (!(key->u.s.ad = heap_alloc(secret_len))) return STATUS_NO_MEMORY;
    //if (!(key->u.s.tag = heap_alloc(secret_len))) return STATUS_NO_MEMORY;
    memcpy(buffer, secret, secret_len);

    key->alg_id = alg->id;
    key->u.s.mode = alg->mode;
    //key->u.s.handle = 0;        /* initialized on first use */
    key->u.s.secret = buffer;
    key->u.s.secret_len = secret_len;
    key->u.s.iv = 0;
    key->u.s.iv_len = 0;
    key->u.s.ad = 0;
    key->u.s.ad_len = 0;
    key->u.s.tag = 0;
    key->u.s.tag_len = 0;

    if (!(key->u.s.decrypt_handle = heap_alloc(sizeof(mbedtls_cipher_context_t)))) return STATUS_NO_MEMORY;
    if (!(key->u.s.encrypt_handle = heap_alloc(sizeof(mbedtls_cipher_context_t)))) return STATUS_NO_MEMORY;
    key_bitlen = key->u.s.secret_len * 8;
    if (!(info = mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, key_bitlen, mode))) return STATUS_INTERNAL_ERROR;
    if ((ret = mbedtls_cipher_setup(key->u.s.decrypt_handle, info))) return STATUS_INTERNAL_ERROR;
    if ((ret = mbedtls_cipher_setkey(key->u.s.decrypt_handle, key->u.s.secret, key_bitlen, MBEDTLS_DECRYPT))) return STATUS_INTERNAL_ERROR;
    if (mode == MBEDTLS_MODE_CBC && (ret = mbedtls_cipher_set_padding_mode(key->u.s.decrypt_handle, MBEDTLS_PADDING_NONE))) return STATUS_INTERNAL_ERROR;
    if ((ret = mbedtls_cipher_setup(key->u.s.encrypt_handle, info))) return STATUS_INTERNAL_ERROR;
    if ((ret = mbedtls_cipher_setkey(key->u.s.encrypt_handle, key->u.s.secret, key_bitlen, MBEDTLS_ENCRYPT))) return STATUS_INTERNAL_ERROR;
    if (mode == MBEDTLS_MODE_CBC && (ret = mbedtls_cipher_set_padding_mode(key->u.s.encrypt_handle, MBEDTLS_PADDING_NONE))) return STATUS_INTERNAL_ERROR;

    return STATUS_SUCCESS;
}


NTSTATUS key_symmetric_set_params( struct key *key, UCHAR *iv, ULONG iv_len )
{
    mbedtls_cipher_type_t cipher;

    if (!key->u.s.decrypt_handle || !key->u.s.encrypt_handle)
    {
        return STATUS_INTERNAL_ERROR;
    }

    if ((cipher = get_mbedtls_cipher(key)) == MBEDTLS_CIPHER_NONE)
        return STATUS_NOT_SUPPORTED;

    if (iv)
    {
        if (key->u.s.iv) heap_free(key->u.s.iv);
        if (!(key->u.s.iv = heap_alloc(iv_len))) return STATUS_INTERNAL_ERROR;
        memcpy(key->u.s.iv, iv, iv_len);
        key->u.s.iv_len = iv_len;
    }

    return STATUS_SUCCESS;
}

NTSTATUS key_symmetric_set_auth_data( struct key *key, UCHAR *auth_data, ULONG len )
{
    if (!auth_data || !len) return STATUS_INTERNAL_ERROR;
    if (key->u.s.ad) heap_free(key->u.s.ad);
    if (!(key->u.s.ad = heap_alloc(len))) return STATUS_NO_MEMORY;
    memcpy(key->u.s.ad, auth_data, len);
    key->u.s.ad_len = len;

    return STATUS_SUCCESS;
}

NTSTATUS key_symmetric_encrypt( struct key *key, const UCHAR *input, ULONG input_len, UCHAR *output, ULONG output_len )
{
    int ret;
    ULONG output_len_out = output_len;
    UCHAR *buf;

    if (key->u.s.mode == MODE_ID_GCM)
    {
        if (key->u.s.tag) heap_free(key->u.s.tag);
        if (!(key->u.s.tag = heap_alloc(key->u.s.block_size))) return STATUS_NO_MEMORY;
        key->u.s.tag_len = key->u.s.block_size;
        if ((ret = mbedtls_cipher_auth_encrypt(key->u.s.encrypt_handle, key->u.s.iv, key->u.s.iv_len, key->u.s.ad, key->u.s.ad_len, input, input_len, output, &output_len_out, key->u.s.tag, key->u.s.tag_len)))
        {
            return STATUS_INTERNAL_ERROR;
        }
    }
    else
    {
        buf = heap_alloc(input_len + key->u.s.block_size);
        if ((ret = mbedtls_cipher_crypt(key->u.s.encrypt_handle, key->u.s.iv, key->u.s.iv_len, input, input_len, buf, &output_len_out)))
        {
            heap_free(buf);
            return STATUS_INTERNAL_ERROR;
        }
        memcpy(output, buf, output_len_out);
        heap_free(buf);
    }

    return STATUS_SUCCESS;
}

NTSTATUS key_symmetric_decrypt( struct key *key, const UCHAR *input, ULONG input_len, UCHAR *output, ULONG output_len, UCHAR *tag, ULONG tag_len)
{
    int ret;
    ULONG output_len_out = output_len;
    UCHAR *buf;

    if (key->u.s.mode == MODE_ID_GCM)
    {
        if ((ret = mbedtls_cipher_auth_decrypt(key->u.s.decrypt_handle, key->u.s.iv, key->u.s.iv_len, key->u.s.ad, key->u.s.ad_len, input, input_len, output, &output_len_out, tag, tag_len)))
        {
            if (ret == MBEDTLS_ERR_CIPHER_AUTH_FAILED)
                return STATUS_AUTH_TAG_MISMATCH;
            return STATUS_INTERNAL_ERROR;
        }
        if (key->u.s.tag) heap_free(key->u.s.tag);
        if (!(key->u.s.tag = heap_alloc(tag_len))) return STATUS_NO_MEMORY;
        memcpy(tag, key->u.s.tag, tag_len);
        key->u.s.tag_len = tag_len;
        if (output_len_out > output_len)
        {
            key->u.s.output_len = output_len_out;
            return STATUS_BUFFER_TOO_SMALL;
        }
    }
    else
    {
        buf = heap_alloc(input_len+output_len+key->u.s.block_size);
        if ((ret = mbedtls_cipher_crypt(key->u.s.decrypt_handle, key->u.s.iv, key->u.s.iv_len, input, input_len, buf, &output_len_out)))
        {
            heap_free(buf);
            return STATUS_INTERNAL_ERROR;
        }
        memcpy(output, buf, output_len_out);
        heap_free(buf);
        if (output_len_out > output_len)
        {
            key->u.s.output_len = output_len_out;
            return STATUS_BUFFER_TOO_SMALL;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS key_symmetric_get_tag( struct key *key, UCHAR *tag, ULONG len )
{
    if (!tag || !len) return STATUS_INTERNAL_ERROR;
    if (!key->u.s.tag) return STATUS_INTERNAL_ERROR;
    if (len < key->u.s.tag_len) STATUS_BUFFER_TOO_SMALL;
    memcpy(tag, key->u.s.tag, key->u.s.tag_len);

    return STATUS_SUCCESS;
}

NTSTATUS key_asymmetric_init( struct key *key, struct algorithm *alg, const UCHAR *pubkey, ULONG pubkey_len )
{
    UCHAR *buffer;
    const mbedtls_pk_info_t* info;
    mbedtls_pk_type_t type = MBEDTLS_PK_NONE;
    //ULONG offset, magic, size;
    //BCRYPT_ECCKEY_BLOB *eccblob = (BCRYPT_ECCKEY_BLOB *)pubkey;
    //BCRYPT_RSAKEY_BLOB *rsablob = (BCRYPT_RSAKEY_BLOB *)pubkey;

    switch (alg->id)
    {
    case ALG_ID_ECDSA_P256:
    case ALG_ID_ECDSA_P384:
        type = MBEDTLS_PK_ECDSA;
        break;
    case ALG_ID_RSA:
        type = MBEDTLS_PK_RSA;
        break;

    default:
        FIXME("algorithm %u not supported\n", alg->id);
        return STATUS_NOT_SUPPORTED;
    }
    //TRACE("blob magic %08x\n", magic);

    if (!(buffer = heap_alloc(pubkey_len))) return STATUS_NO_MEMORY;
    memcpy(buffer, pubkey, pubkey_len);

    key->alg_id = alg->id;
    key->u.a.pubkey = buffer;
    key->u.a.pubkey_len = pubkey_len;
    if (!(key->u.a.handle = heap_alloc(sizeof(mbedtls_pk_context)))) return STATUS_NO_MEMORY;
    if (!(info = mbedtls_pk_info_from_type(type))) return STATUS_INTERNAL_ERROR;
    if (!(mbedtls_pk_setup(key->u.a.handle, info))) return STATUS_INTERNAL_ERROR;
    if (!(import_mbedtls_pubkey(key))) return STATUS_INTERNAL_ERROR;

    return STATUS_SUCCESS;
}



NTSTATUS key_asymmetric_verify( struct key *key, void *padding, UCHAR *hash, ULONG hash_len, UCHAR *signature,
                                ULONG signature_len, DWORD flags )
{
    mbedtls_md_type_t hash_algo;
    int ret;

    if (key->alg_id == ALG_ID_RSA)
    {
        BCRYPT_PKCS1_PADDING_INFO *pinfo = (BCRYPT_PKCS1_PADDING_INFO *)padding;

        if (!(flags & BCRYPT_PAD_PKCS1) || !pinfo) return STATUS_INVALID_PARAMETER;
        if (!pinfo->pszAlgId) return STATUS_INVALID_SIGNATURE;

        if (!strcmpW(pinfo->pszAlgId, BCRYPT_SHA1_ALGORITHM)) hash_algo = MBEDTLS_MD_SHA1;
        else if (!strcmpW(pinfo->pszAlgId, BCRYPT_SHA256_ALGORITHM)) hash_algo = MBEDTLS_MD_SHA256;
        else if (!strcmpW(pinfo->pszAlgId, BCRYPT_SHA384_ALGORITHM)) hash_algo = MBEDTLS_MD_SHA384;
        else if (!strcmpW(pinfo->pszAlgId, BCRYPT_SHA512_ALGORITHM)) hash_algo = MBEDTLS_MD_SHA512;
        else
        {
            FIXME("Hash algorithm %s not supported\n", debugstr_w(pinfo->pszAlgId));
            return STATUS_NOT_SUPPORTED;
        }
    }
    else
    {
        if (flags)
            FIXME("Flags %08x not supported\n", flags);

        // only the hash size must match, not the actual hash function
        switch (hash_len)
        {
        case 32: hash_algo = MBEDTLS_MD_SHA256; break;
        case 48: hash_algo = MBEDTLS_MD_SHA384; break;

        default:
            FIXME("Hash size %u not yet supported\n", hash_len);
            return STATUS_INVALID_SIGNATURE;
        }
    }

    ret = mbedtls_pk_verify(key->u.a.handle, hash_algo, hash, hash_len, signature, signature_len);

    return (ret != 0) ? STATUS_INVALID_SIGNATURE : STATUS_SUCCESS;
}

NTSTATUS key_destroy( struct key *key )
{
    if (key_is_symmetric(key))
    {
        mbedtls_cipher_free(key->u.s.decrypt_handle);
        mbedtls_cipher_free(key->u.s.encrypt_handle);
        heap_free(key->u.s.decrypt_handle);
        heap_free(key->u.s.encrypt_handle);
        heap_free(key->u.s.secret);
        if (key->u.s.ad) heap_free(key->u.s.ad);
        if (key->u.s.iv) heap_free(key->u.s.iv);
        if (key->u.s.tag) heap_free(key->u.s.tag);
    }
    else
        heap_free(key->u.a.pubkey);
    heap_free(key);
    return STATUS_SUCCESS;
}

