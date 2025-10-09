package utils

import (
	"fmt"
	"encoding/binary"
	"github.com/miekg/pkcs11"
)

// AttrToString converts a single *pkcs11.Attribute to a human-readable string like "CKA_CLASS: CKO_PUBLIC_KEY".
// Handles common types; falls back to hex for unknowns.
func AttrToString(attr *pkcs11.Attribute) string {
    typeName := getAttrName(attr.Type)
    var valStr string

    switch attr.Type {
    // Enums: Object classes
    case pkcs11.CKA_CLASS:
        if len(attr.Value) == 8 {
			class := binary.LittleEndian.Uint32(attr.Value[:4])
            valStr = getObjectClassName(class)
        }

    // Enums: Key types
    case pkcs11.CKA_KEY_TYPE:
        if len(attr.Value) == 8 {
			keyType := binary.LittleEndian.Uint32(attr.Value[:4])
            valStr = getKeyTypeName(keyType)
        }

    // Enums: Certificate types (for CKA_CERTIFICATE_TYPE)
    case pkcs11.CKA_CERTIFICATE_TYPE:
        if len(attr.Value) == 8 {
            certType := binary.LittleEndian.Uint32(attr.Value[:4])
            switch certType {
            case 0x00000000: valStr = "CKC_X_509"
            case 0x00000001: valStr = "CKC_X_509_ATTR_CERT"
            case 0x00000002: valStr = "CKC_WTLS"
            case 0x00000003: valStr = "CKC_VENDOR_DEFINED"
            default: valStr = fmt.Sprintf("CKC_UNKNOWN(0x%08x)", certType)
            }
        }

    // Mechanism types (e.g., for CKA_KEY_GEN_MECHANISM)
    case pkcs11.CKA_KEY_GEN_MECHANISM:
        if len(attr.Value) == 8 {
            mech := binary.LittleEndian.Uint32(attr.Value[:4])
            valStr = getMechanismName(mech)
        }

    // Booleans (single byte: 0x00=false, 0xFF=true)
    case pkcs11.CKA_TOKEN, pkcs11.CKA_PRIVATE, pkcs11.CKA_SENSITIVE,
         pkcs11.CKA_ENCRYPT, pkcs11.CKA_DECRYPT, pkcs11.CKA_WRAP,
         pkcs11.CKA_UNWRAP, pkcs11.CKA_SIGN, pkcs11.CKA_SIGN_RECOVER,
         pkcs11.CKA_VERIFY, pkcs11.CKA_VERIFY_RECOVER, pkcs11.CKA_DERIVE,
         pkcs11.CKA_EXTRACTABLE, pkcs11.CKA_LOCAL, pkcs11.CKA_NEVER_EXTRACTABLE,
         pkcs11.CKA_ALWAYS_SENSITIVE, pkcs11.CKA_MODIFIABLE, pkcs11.CKA_COPYABLE,
         pkcs11.CKA_DESTROYABLE, pkcs11.CKA_ALWAYS_AUTHENTICATE, pkcs11.CKA_TRUSTED:
        valStr = "false"
        if len(attr.Value) == 1 && attr.Value[0] == 0xFF {
            valStr = "true"
        }

    // Strings
    case pkcs11.CKA_LABEL, pkcs11.CKA_APPLICATION, pkcs11.CKA_SUBJECT,
         pkcs11.CKA_ISSUER, pkcs11.CKA_SERIAL_NUMBER, pkcs11.CKA_URL:
        valStr = fmt.Sprintf("%q", string(attr.Value)) // Quoted for readability

    // Dates (8-byte YYYYMMDDhhmmss00, but simplified to string)
    case pkcs11.CKA_START_DATE, pkcs11.CKA_END_DATE:
        if len(attr.Value) == 16 { // Often padded
            valStr = string(attr.Value[:8]) // YYYYMMDDhhmmss00 -> YYYY-MM-DD hh:mm:ss (manual format if needed)
        } else {
            valStr = string(attr.Value)
        }

    // Small integers (uint32)
    case pkcs11.CKA_MODULUS_BITS, pkcs11.CKA_PRIME_BITS, pkcs11.CKA_SUBPRIME_BITS,
         pkcs11.CKA_VALUE_BITS, pkcs11.CKA_VALUE_LEN:
        if len(attr.Value) == 8 {
            num := binary.LittleEndian.Uint32(attr.Value[:4])
            valStr = fmt.Sprintf("%d", num)
        }

    // Binary data (hex dump)
    case pkcs11.CKA_VALUE, pkcs11.CKA_ID, pkcs11.CKA_MODULUS,
         pkcs11.CKA_PUBLIC_EXPONENT, pkcs11.CKA_PRIVATE_EXPONENT,
         pkcs11.CKA_PRIME_1, pkcs11.CKA_PRIME_2, pkcs11.CKA_EXPONENT_1,
         pkcs11.CKA_EXPONENT_2, pkcs11.CKA_COEFFICIENT, pkcs11.CKA_PRIME,
         pkcs11.CKA_SUBPRIME, pkcs11.CKA_BASE, pkcs11.CKA_EC_PARAMS,
         pkcs11.CKA_EC_POINT, pkcs11.CKA_PUBLIC_KEY_INFO, pkcs11.CKA_CHECK_VALUE:
        valStr = fmt.Sprintf("0x%x", attr.Value) // Compact hex

    // Other arrays (e.g., CKA_WRAP_TEMPLATE) - treat as hex
    case pkcs11.CKA_WRAP_TEMPLATE, pkcs11.CKA_UNWRAP_TEMPLATE,
         pkcs11.CKA_ATTR_TYPES:
        valStr = fmt.Sprintf("0x%x", attr.Value)

    // Fallback for unknowns
    default:
        valStr = fmt.Sprintf("0x%x", attr.Value)
    }

    return fmt.Sprintf("%s: %s", typeName, valStr)
}

// getAttrName returns the string name for an attribute type.
func getAttrName(t uint) string {
    attrNames := map[uint]string{
        // Core attributes
        pkcs11.CKA_CLASS:                "CKA_CLASS",
        pkcs11.CKA_TOKEN:                "CKA_TOKEN",
        pkcs11.CKA_PRIVATE:              "CKA_PRIVATE",
        pkcs11.CKA_LABEL:                "CKA_LABEL",
        pkcs11.CKA_APPLICATION:          "CKA_APPLICATION",
        pkcs11.CKA_VALUE:                "CKA_VALUE",
        pkcs11.CKA_OBJECT_ID:            "CKA_OBJECT_ID",
        pkcs11.CKA_CERTIFICATE_TYPE:     "CKA_CERTIFICATE_TYPE",
        pkcs11.CKA_ISSUER:               "CKA_ISSUER",
        pkcs11.CKA_SERIAL_NUMBER:        "CKA_SERIAL_NUMBER",
        pkcs11.CKA_AC_ISSUER:            "CKA_AC_ISSUER",
        pkcs11.CKA_OWNER:                "CKA_OWNER",
        pkcs11.CKA_ATTR_TYPES:           "CKA_ATTR_TYPES",
        pkcs11.CKA_TRUSTED:              "CKA_TRUSTED",
        pkcs11.CKA_CERTIFICATE_CATEGORY: "CKA_CERTIFICATE_CATEGORY",
        pkcs11.CKA_JAVA_MIDP_SECURITY_DOMAIN: "CKA_JAVA_MIDP_SECURITY_DOMAIN",
        pkcs11.CKA_URL:                  "CKA_URL",
        pkcs11.CKA_HASH_OF_SUBJECT_PUBLIC_KEY: "CKA_HASH_OF_SUBJECT_PUBLIC_KEY",
        pkcs11.CKA_HASH_OF_ISSUER_PUBLIC_KEY:  "CKA_HASH_OF_ISSUER_PUBLIC_KEY",
        pkcs11.CKA_CHECK_VALUE:          "CKA_CHECK_VALUE",

        // Key attributes
        pkcs11.CKA_KEY_TYPE:             "CKA_KEY_TYPE",
        pkcs11.CKA_SUBJECT:              "CKA_SUBJECT",
        pkcs11.CKA_ID:                   "CKA_ID",
        pkcs11.CKA_SENSITIVE:            "CKA_SENSITIVE",
        pkcs11.CKA_ENCRYPT:              "CKA_ENCRYPT",
        pkcs11.CKA_DECRYPT:              "CKA_DECRYPT",
        pkcs11.CKA_WRAP:                 "CKA_WRAP",
        pkcs11.CKA_UNWRAP:               "CKA_UNWRAP",
        pkcs11.CKA_SIGN:                 "CKA_SIGN",
        pkcs11.CKA_SIGN_RECOVER:         "CKA_SIGN_RECOVER",
        pkcs11.CKA_VERIFY:               "CKA_VERIFY",
        pkcs11.CKA_VERIFY_RECOVER:       "CKA_VERIFY_RECOVER",
        pkcs11.CKA_DERIVE:               "CKA_DERIVE",
        pkcs11.CKA_START_DATE:           "CKA_START_DATE",
        pkcs11.CKA_END_DATE:             "CKA_END_DATE",
        pkcs11.CKA_MODULUS:              "CKA_MODULUS",
        pkcs11.CKA_MODULUS_BITS:         "CKA_MODULUS_BITS",
        pkcs11.CKA_PUBLIC_EXPONENT:      "CKA_PUBLIC_EXPONENT",
        pkcs11.CKA_PRIVATE_EXPONENT:     "CKA_PRIVATE_EXPONENT",
        pkcs11.CKA_PRIME_1:              "CKA_PRIME_1",
        pkcs11.CKA_PRIME_2:              "CKA_PRIME_2",
        pkcs11.CKA_EXPONENT_1:           "CKA_EXPONENT_1",
        pkcs11.CKA_EXPONENT_2:           "CKA_EXPONENT_2",
        pkcs11.CKA_COEFFICIENT:          "CKA_COEFFICIENT",
        pkcs11.CKA_PUBLIC_KEY_INFO:      "CKA_PUBLIC_KEY_INFO",
        pkcs11.CKA_PRIME:                "CKA_PRIME",
        pkcs11.CKA_SUBPRIME:             "CKA_SUBPRIME",
        pkcs11.CKA_BASE:                 "CKA_BASE",
        pkcs11.CKA_PRIME_BITS:           "CKA_PRIME_BITS",
        pkcs11.CKA_SUBPRIME_BITS:        "CKA_SUBPRIME_BITS",
        pkcs11.CKA_VALUE_BITS:           "CKA_VALUE_BITS",
        pkcs11.CKA_VALUE_LEN:            "CKA_VALUE_LEN",
        pkcs11.CKA_EXTRACTABLE:          "CKA_EXTRACTABLE",
        pkcs11.CKA_LOCAL:                "CKA_LOCAL",
        pkcs11.CKA_NEVER_EXTRACTABLE:    "CKA_NEVER_EXTRACTABLE",
        pkcs11.CKA_ALWAYS_SENSITIVE:     "CKA_ALWAYS_SENSITIVE",
        pkcs11.CKA_KEY_GEN_MECHANISM:    "CKA_KEY_GEN_MECHANISM",
        pkcs11.CKA_MODIFIABLE:           "CKA_MODIFIABLE",
        pkcs11.CKA_COPYABLE:             "CKA_COPYABLE",
        pkcs11.CKA_DESTROYABLE:          "CKA_DESTROYABLE",
        pkcs11.CKA_EC_PARAMS:            "CKA_EC_PARAMS",
        pkcs11.CKA_EC_POINT:             "CKA_EC_POINT",
        pkcs11.CKA_ALWAYS_AUTHENTICATE:  "CKA_ALWAYS_AUTHENTICATE",
        pkcs11.CKA_WRAP_WITH_TRUSTED:    "CKA_WRAP_WITH_TRUSTED",
        pkcs11.CKA_WRAP_TEMPLATE:        "CKA_WRAP_TEMPLATE",
        pkcs11.CKA_UNWRAP_TEMPLATE:      "CKA_UNWRAP_TEMPLATE",
    }
    if name, ok := attrNames[t]; ok {
        return name
    }
    return fmt.Sprintf("CKA_UNKNOWN(0x%08x)", t)
}

// getObjectClassName maps CKO_ values to strings.
func getObjectClassName(class uint32) string {
    switch class {
    case pkcs11.CKO_DATA: return "CKO_DATA"
    case pkcs11.CKO_CERTIFICATE: return "CKO_CERTIFICATE"
    case pkcs11.CKO_PUBLIC_KEY: return "CKO_PUBLIC_KEY"
    case pkcs11.CKO_PRIVATE_KEY: return "CKO_PRIVATE_KEY"
    case pkcs11.CKO_SECRET_KEY: return "CKO_SECRET_KEY"
    case pkcs11.CKO_HW_FEATURE: return "CKO_HW_FEATURE"
    case pkcs11.CKO_DOMAIN_PARAMETERS: return "CKO_DOMAIN_PARAMETERS"
    case pkcs11.CKO_MECHANISM: return "CKO_MECHANISM"
    case pkcs11.CKO_OTP_KEY: return "CKO_OTP_KEY"
    case 0x80000000: return "CKO_VENDOR_DEFINED"
    default: return fmt.Sprintf("CKO_UNKNOWN(0x%08x)", class)
    }
}

// getKeyTypeName maps CKK_ values to strings.
func getKeyTypeName(keyType uint32) string {
    switch keyType {
    case pkcs11.CKK_RSA: return "CKK_RSA"
    case pkcs11.CKK_DSA: return "CKK_DSA"
    case pkcs11.CKK_DH: return "CKK_DH"
    case pkcs11.CKK_EC: return "CKK_ECDSA"
    case pkcs11.CKK_X9_42_DH: return "CKK_X9_42_DH"
    case pkcs11.CKK_KEA: return "CKK_KEA"
    case pkcs11.CKK_GENERIC_SECRET: return "CKK_GENERIC_SECRET"
    case pkcs11.CKK_RC2: return "CKK_RC2"
    case pkcs11.CKK_RC4: return "CKK_RC4"
    case pkcs11.CKK_DES: return "CKK_DES"
    case pkcs11.CKK_DES2: return "CKK_DES2"
    case pkcs11.CKK_DES3: return "CKK_DES3"
    case pkcs11.CKK_CAST: return "CKK_CAST"
    case pkcs11.CKK_CAST3: return "CKK_CAST3"
    case pkcs11.CKK_CAST128: return "CKK_CAST128"
    case pkcs11.CKK_RC5: return "CKK_RC5"
    case pkcs11.CKK_IDEA: return "CKK_IDEA"
    case pkcs11.CKK_SKIPJACK: return "CKK_SKIPJACK"
    case pkcs11.CKK_BATON: return "CKK_BATON"
    case pkcs11.CKK_JUNIPER: return "CKK_JUNIPER"
    case pkcs11.CKK_CDMF: return "CKK_CDMF"
    case pkcs11.CKK_AES: return "CKK_AES"
    case pkcs11.CKK_BLOWFISH: return "CKK_BLOWFISH"
    case pkcs11.CKK_TWOFISH: return "CKK_TWOFISH"
    case pkcs11.CKK_SECURID: return "CKK_SECURID"
    case pkcs11.CKK_HOTP: return "CKK_HOTP"
    case pkcs11.CKK_ACTI: return "CKK_ACTI"
    case pkcs11.CKK_CAMELLIA: return "CKK_CAMELLIA"
    case pkcs11.CKK_ARIA: return "CKK_ARIA"
    case pkcs11.CKK_MD5_HMAC: return "CKK_MD5_HMAC"
    case pkcs11.CKK_SHA_1_HMAC: return "CKK_SHA_1_HMAC"
    case pkcs11.CKK_RIPEMD128_HMAC: return "CKK_RIPEMD128_HMAC"
    case pkcs11.CKK_RIPEMD160_HMAC: return "CKK_RIPEMD160_HMAC"
    case pkcs11.CKK_SHA256_HMAC: return "CKK_SHA256_HMAC"
    case pkcs11.CKK_SHA384_HMAC: return "CKK_SHA384_HMAC"
    case pkcs11.CKK_SHA512_HMAC: return "CKK_SHA512_HMAC"
    case pkcs11.CKK_SEED: return "CKK_SEED"
    case pkcs11.CKK_GOSTR3410: return "CKK_GOSTR3410"
    case pkcs11.CKK_GOSTR3411: return "CKK_GOSTR3411"
    default: return fmt.Sprintf("CKK_UNKNOWN(0x%08x)", keyType)
    }
}

// getMechanismName maps common CKM_ values to strings (partial list; extend as needed).
func getMechanismName(mech uint32) string {
    switch mech {
    case pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN: return "CKM_RSA_PKCS_KEY_PAIR_GEN"
    case pkcs11.CKM_RSA_PKCS: return "CKM_RSA_PKCS"
    case pkcs11.CKM_RSA_PKCS_OAEP: return "CKM_RSA_PKCS_OAEP"
    case pkcs11.CKM_AES_KEY_GEN: return "CKM_AES_KEY_GEN"
    case pkcs11.CKM_AES_ECB: return "CKM_AES_ECB"
    case pkcs11.CKM_AES_CBC: return "CKM_AES_CBC"
    case pkcs11.CKM_AES_CBC_PAD: return "CKM_AES_CBC_PAD"
    case pkcs11.CKM_AES_GCM: return "CKM_AES_GCM"
    case pkcs11.CKM_SHA_1: return "CKM_SHA1"
    case pkcs11.CKM_SHA256: return "CKM_SHA256"
    case pkcs11.CKM_ECDSA: return "CKM_ECDSA"
    case pkcs11.CKM_EC_KEY_PAIR_GEN: return "CKM_EC_KEY_PAIR_GEN"
    default: return fmt.Sprintf("CKM_UNKNOWN(0x%08x)", mech)
    }
}
