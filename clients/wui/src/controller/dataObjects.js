// OpenPGP data object tags, ported from pytools/gpgapp/gpgcmd.py.
// Used by GET DATA (0xCA) / PUT DATA (0xDA) for backup and restore.

export const DO = Object.freeze({
  // Slot config / RSA exponent (Ledger specific commands)
  SLOT_CFG: 0x01f1, // [R/W] Slot config
  SLOT_CUR: 0x01f2, // [R/W] Slot selection
  RSA_EXP: 0x01f8, // [R/W] RSA exponent

  AID: 0x4f, // [R] Full Application identifier (ISO 7816-4)
  LOGIN: 0x5e, // [R/W] Login data
  URL: 0x5f50, // [R/W] URL (RFC 1738)
  HIST: 0x5f52, // [R] Historical bytes

  // Optional private-use data objects
  PRIVATE_01: 0x0101,
  PRIVATE_02: 0x0102,
  PRIVATE_03: 0x0103,
  PRIVATE_04: 0x0104,

  CARDHOLDER_DATA: 0x65, // [R] Cardholder Related Data
  CARD_NAME: 0x5b, // [R/W] Name (ISO/IEC 7501-1)
  CARD_LANG: 0x5f2d, // [R/W] Language preferences (ISO 639)
  CARD_SALUTATION: 0x5f35, // [R/W] Salutation (ISO 5218)

  SIG_KEY: 0xb6, // [R/W] Digital signature key
  DEC_KEY: 0xb8, // [R/W] Confidentiality key
  AUT_KEY: 0xa4, // [R/W] Authentication key

  APP_DATA: 0x6e, // [R] Application Related Data
  EXT_LEN: 0x7f66, // [R] Extended length info (ISO 7816-4)
  DISCRET_DATA: 0x73, // [R] Discretionary data objects

  EXT_CAP: 0xc0, // [R] Extended capabilities flag list
  SIG_ATTR: 0xc1, // [R/W] Algorithm attributes SIGnature
  DEC_ATTR: 0xc2, // [R/W] Algorithm attributes DECryption
  AUT_ATTR: 0xc3, // [R/W] Algorithm attributes AUThentication
  PW_STATUS: 0xc4, // [R/W] PW status bytes
  FINGERPRINTS: 0xc5, // [R] Fingerprints (3 x 20 bytes)
  CA_FINGERPRINTS: 0xc6, // [R] CA-Fingerprints (3 x 20 bytes)
  FINGERPRINT_WR_SIG: 0xc7, // [W] Fingerprint for SIG key
  FINGERPRINT_WR_DEC: 0xc8, // [W] Fingerprint for DEC key
  FINGERPRINT_WR_AUT: 0xc9, // [W] Fingerprint for AUT key
  CA_FINGERPRINT_WR_SIG: 0xca, // [W] CA-Fingerprint for SIG key
  CA_FINGERPRINT_WR_DEC: 0xcb, // [W] CA-Fingerprint for DEC key
  CA_FINGERPRINT_WR_AUT: 0xcc, // [W] CA-Fingerprint for AUT key
  KEY_DATES: 0xcd, // [R] Generation dates (3 x 4 bytes BE)

  DATES_WR_SIG: 0xce, // [W] Generation date/time of SIG key
  DATES_WR_DEC: 0xcf, // [W] Generation date/time of DEC key
  DATES_WR_AUT: 0xd0, // [W] Generation date/time of AUT key

  SEC_TEMPL: 0x7a, // [R] Security support template
  SIG_COUNT: 0x93, // [R] Digital signature counter

  RESET_CODE: 0xd3, // [W] Resetting Code
  UIF_SIG: 0xd6, // [R/W] User Interaction Flag for PSO:CDS
  UIF_DEC: 0xd7, // [R/W] User Interaction Flag for PSO:DEC
  UIF_AUT: 0xd8, // [R/W] User Interaction Flag for PSO:AUT
  CERT: 0x7f21, // [R/W] Cardholder certificate (AUT, DEC, SIG)

  PUB_KEY: 0x7f49, // [R/W] Asymmetric key pair
  GEN_FEATURES: 0x7f74, // [R] General Feature management
});

// Human-readable names for the data objects written during a restore, used to
// report which writes the card rejected.
export const DO_NAMES = Object.freeze({
  [DO.AID]: "Serial number (AID)",
  [DO.PW_STATUS]: "PW status",
  [DO.PRIVATE_01]: "Private DO 1",
  [DO.PRIVATE_02]: "Private DO 2",
  [DO.PRIVATE_03]: "Private DO 3",
  [DO.PRIVATE_04]: "Private DO 4",
  [DO.CARD_NAME]: "Cardholder name",
  [DO.LOGIN]: "Login",
  [DO.CARD_LANG]: "Language",
  [DO.URL]: "URL",
  [DO.CARD_SALUTATION]: "Salutation",
  [DO.SIG_ATTR]: "Signature key attributes",
  [DO.DEC_ATTR]: "Decryption key attributes",
  [DO.AUT_ATTR]: "Authentication key attributes",
  [DO.UIF_SIG]: "Signature UIF",
  [DO.UIF_DEC]: "Decryption UIF",
  [DO.UIF_AUT]: "Authentication UIF",
  [DO.SIG_COUNT]: "Signature counter",
  [DO.RSA_EXP]: "RSA exponent",
  [DO.CERT]: "Certificate",
  [DO.CA_FINGERPRINT_WR_SIG]: "Signature CA-fingerprint",
  [DO.CA_FINGERPRINT_WR_DEC]: "Decryption CA-fingerprint",
  [DO.CA_FINGERPRINT_WR_AUT]: "Authentication CA-fingerprint",
  [DO.FINGERPRINT_WR_SIG]: "Signature fingerprint",
  [DO.FINGERPRINT_WR_DEC]: "Decryption fingerprint",
  [DO.FINGERPRINT_WR_AUT]: "Authentication fingerprint",
  [DO.DATES_WR_SIG]: "Signature key date",
  [DO.DATES_WR_DEC]: "Decryption key date",
  [DO.DATES_WR_AUT]: "Authentication key date",
  [DO.SIG_KEY]: "Signature key",
  [DO.DEC_KEY]: "Decryption key",
  [DO.AUT_KEY]: "Authentication key",
});

export function doName(tag) {
  return DO_NAMES[tag] || `DO 0x${tag.toString(16).toUpperCase()}`;
}

// Salutation values (ISO 5218), as encoded in tag 0x5F35.
export const USER_SALUTATION = Object.freeze({
  Male: "1",
  Female: "2",
});

// Key generation algorithm templates (tags C1/C2/C3 attribute values).
export const KEY_TEMPLATES = Object.freeze({
  rsa2048: "010800002001",
  rsa3072: "010c00002001",
  rsa4096: "011000002001",
  nistp256: "132a8648ce3d030107",
  ed25519: "162b06010401da470f01",
  cv25519: "122b060104019755010501",
});
