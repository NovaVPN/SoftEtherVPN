#ifndef	IPSEC_IKEv2_PACKET_H
#define	IPSEC_IKEv2_PACKET_H

#ifndef __DEBUG_SHORTEN_MACROS__
#define __DEBUG_SHORTEN_MACROS__
#endif

#include <stdio.h>
#include <stddef.h>
#include <time.h>"

#include "Mayaqua/MayaType.h"

#define Dbg(text, ...) Debug("[%s %s][%ul] %s:%u %s " text "\n", __DATE__, __TIME__, (unsigned long) time(NULL), __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define DbgBuf(text, buf) DbgPointer(text, buf->Buf, buf->Size)

// This error code returned when malloc/calloc/realloc fails
#define IKEv2_OUT_OF_MEMORY 69

#define IKEv2_LISTEN_PORT 500

#define IKEv2_VERSION 0x20 // 2.0

// IKEv2 Exchange types
#define IKEv2_SA_INIT			0x22
#define IKEv2_AUTH				0x23
#define IKEv2_CREATE_CHILD_SA	0x24
#define IKEv2_INFORMATIONAL		0x25

// IKEv2 Payload types
#define IKEv2_NO_NEXT_PAYLOAD_T		0x0
#define IKEv2_SA_PAYLOAD_T			0x21
#define IKEv2_KE_PAYLOAD_T			0x22
#define IKEv2_IDi_PAYLOAD_T			0x23
#define IKEv2_IDr_PAYLOAD_T			0x24
#define IKEv2_CERTIFICATE_PAYLOAD_T	0x25
#define IKEv2_CERTREQ_PAYLOAD_T		0x26
#define IKEv2_AUTH_PAYLOAD_T		0x27
#define IKEv2_NONCE_PAYLOAD_T		0x28
#define IKEv2_NOTIFY_PAYLOAD_T		0x29
#define IKEv2_DELETE_PAYLOAD_T		0x2A
#define IKEv2_VENDOR_PAYLOAD_T		0x2B
#define IKEv2_TSi_PAYLOAD_T			0x2C
#define IKEv2_TSr_PAYLOAD_T			0x2D
#define IKEv2_SK_PAYLOAD_T			0x2E // Encrypted and Authenticated
#define IKEv2_CP_PAYLOAD_T			0x2F // Configuration
#define IKEv2_EAP_PAYLOAD_T			0x30 // Extensible Auth

/* This bit MUST be cleared in all request messages and MUST be set in all
 * responses */
#define IKEv2_RESPONSE_FLAG   (1 << 5)

/*  Implementations of IKEv2 MUST clear this bit when sending and
 * MUST ignore it in incoming messages. */
#define IKEv2_VERSION_FLAG    (1 << 4)

/* This bit MUST be set in messages sent by the
 * original initiator of the IKE SA and MUST be cleared in
 * messages sent by the original responder */
#define IKEv2_INITIATOR_FLAG  (1 << 3)


/* Security Parameter Index(SPI) Each endpoint chooses one of the two
 * SPIs and MUST choose them so as to be unique identifiers of an IKE
 * SA.  An SPI value of zero is SPECIAL: it indicates that the remote
 * SPI value is not yet known by the sender.
 * The SAi1 payload will be static */

#define IKEv2_HEADER_LENGTH			28
#define IKEv2_MAX_IKE_MESSAGE_LEN	3000

#pragma pack(push, 1)

// IKE header
typedef struct IKEv2_HEADER {
	UINT64 init_SPI;
	UINT64 resp_SPI;
	UCHAR next_payload;
	UCHAR version;
	UCHAR exchange_type;
	UCHAR flags;
	UINT  message_id;
	UINT  message_length;
} IKEv2_HEADER;

// Generic payload header
typedef struct generic_payload {
	UCHAR  next_payload;
	UCHAR  is_critical;
	USHORT payload_length;
} IKEv2_PAYLOAD_HEADER;

#pragma pack(pop)

/* Crypto algorithms SHOULD NOT be implemented if there is no RFC standard */

// SA Payload
#define IKEv2_TRANSFORM_TYPE_ENCR	1
#define IKEv2_TRANSFORM_TYPE_PRF	2
#define IKEv2_TRANSFORM_TYPE_INTEG	3
#define IKEv2_TRANSFORM_TYPE_DH		4
#define IKEv2_TRANSFORM_TYPE_ESN	5

#define IKEv2_TRANSFORM_ID_ENCR_DES_IV64	1
#define IKEv2_TRANSFORM_ID_ENCR_DES			2 // 2405
#define IKEv2_TRANSFORM_ID_ENCR_3DES		3 // 2451
#define IKEv2_TRANSFORM_ID_ENCR_RC5			4 // 2451
#define IKEv2_TRANSFORM_ID_ENCR_IDEA		5 // 2451
#define IKEv2_TRANSFORM_ID_ENCR_CAST		6 // 2451
#define IKEv2_TRANSFORM_ID_ENCR_BLOWFISH	7 // 2451
#define IKEv2_TRANSFORM_ID_ENCR_3IDEA		8
#define IKEv2_TRANSFORM_ID_ENCR_DES_IV32	9
#define IKEv2_TRANSFORM_ID_ENCR_NULL		11 // 2410
#define IKEv2_TRANSFORM_ID_ENCR_AES_CBC		12 // 3602
#define IKEv2_TRANSFORM_ID_ENCR_AES_CTR		13 // 3686

#define IKEv2_TRANSFORM_ID_PRF_HMAC_MD5		1 // 2104
#define IKEv2_TRANSFORM_ID_PRF_HMAC_SHA1	2 // 2104
#define IKEv2_TRANSFORM_ID_PRF_HMAC_TIGER	3

#define IKEv2_TRANSFORM_ID_AUTH_NONE			0 // OK
#define IKEv2_TRANSFORM_ID_AUTH_HMAC_MD5_96		1 // 2403
#define IKEv2_TRANSFORM_ID_AUTH_HMAC_SHA1_96	2 // 2404
#define IKEv2_TRANSFORM_ID_AUTH_DES_MAC			3
#define IKEv2_TRANSFORM_ID_AUTH_KPDK_MD5		4
#define IKEv2_TRANSFORM_ID_AUTH_AES_XCBC_96		5 // 3566

#define IKEv2_TRANSFORM_ID_DH_NONE	0 // not used in IKE
#define IKEv2_TRANSFORM_ID_DH_768	1
#define IKEv2_TRANSFORM_ID_DH_1024	2
#define IKEv2_TRANSFORM_ID_DH_1536	5
#define IKEv2_TRANSFORM_ID_DH_2048	14
#define IKEv2_TRANSFORM_ID_DH_3072	15
#define IKEv2_TRANSFORM_ID_DH_4096	16
#define IKEv2_TRANSFORM_ID_DH_6144	17
#define IKEv2_TRANSFORM_ID_DH_8192	18

#define IKEv2_TRANSFORM_ID_NO_ESN	0
#define IKEv2_TRANSFORM_ID_ESN		1

typedef struct transform_t {
	UCHAR  type;
	USHORT ID;
} transform_t;

#define IKEv2_ATTRIBUTE_TLV_MAX_LENGTH IKEv2_MAX_IKE_MESSAGE_LEN
#define IKEv2_ATTRIBUTE_TYPE_KEY_LENGTH 14

typedef struct IKEv2_TRANSFORM_ATTRIBUTE {
	UCHAR	format; // 0 = TLV, 1 = TV
	USHORT type;
	USHORT value;
	BUF		*TLV_value;
} IKEv2_TRANSFORM_ATTRIBUTE;

typedef struct IKEv2_SA_TRANSFORM {
	bool is_last;
	USHORT transform_length;
	transform_t transform;
	LIST *attributes; // LIST of TRANSFORM_ATTRIBUTE
} IKEv2_SA_TRANSFORM;

/* Protocol IDs */
#define IKEv2_PROPOSAL_PROTOCOL_IKE 1
#define IKEv2_PROPOSAL_PROTOCOL_AH	2
#define IKEv2_PROPOSAL_PROTOCOL_ESP 3

typedef struct IKEv2_SA_PROPOSAL {
	bool	is_last;
	USHORT  length;
	UCHAR	number;
	UCHAR	protocol_id;
	UCHAR	SPI_size;
	UCHAR	transform_number;
	BUF		*SPI;
	LIST	*transforms; // LIST of IKEv2_SA_TRANSFORM
} IKEv2_SA_PROPOSAL;

typedef struct IKEv2_SA_PAYLOAD {
	LIST *proposals;  // LIST of IKEv2_SA_PROPOSAL
} IKEv2_SA_PAYLOAD;
// End of SA Payload

// KE Payload
typedef struct IKEv2_KE_PAYLOAD {
	USHORT DH_transform_ID;
	BUF*   key_data;
} IKEv2_KE_PAYLOAD;
// End of KE Payload

// ID Payload
#define IKEv2_DH_ID_IPV4_ADDR	1
#define IKEv2_DH_ID_FQDN		2
#define IKEv2_DH_ID_RFC822_ADDR	3
#define IKEv2_DH_ID_IPV6_ADDR	5
#define IKEv2_DH_ID_DER_ASN1_DN	9
#define IKEv2_DH_ID_DER_ASN1_GN	10
#define IKEv2_DH_ID_KEY_ID		11

typedef struct IKEv2_ID_PAYLOAD {
	UCHAR ID_type;
	BUF*   data;
} IKEv2_ID_PAYLOAD;
// End of ID Payload

// CERT Payload
#define IKEv2_X_509_CERTIFICATE_SIGNATURE	4
#define IKEv2_CRL_SIGNATURE					7
#define IKEv2_HASH_URL_X_509_CERT			12
#define IKEv2_HASH_URL_X_509_BUNDLE			13

typedef struct IKEv2_CERT_PAYLOAD {
	UCHAR encoding_type;
	BUF* data;
} IKEv2_CERT_PAYLOAD;
// End of CERT Payload

// CERT_REQ Payload
typedef struct IKEv2_CERT_PAYLOAD IKEv2_CERTREQ_PAYLOAD;
// End of CERT_REQ Payload

// AUTH Payload
// Authentication methods
#define IKEv2_AUTH_RSA_DIGITAL_SIGNATURE               1
#define IKEv2_AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE   2
#define IKEv2_AUTH_DSS_DIGITAL_SIGNATURE               3

typedef struct IKEv2_AUTH_PAYLOAD {
	UCHAR auth_method;
	BUF*   data;
} IKEv2_AUTH_PAYLOAD;
// End of AUTH Payload

// NONCE Payload
#define IKEv2_MIN_NONCE_SIZE 16
#define IKEv2_MAX_NONCE_SIZE 256

typedef struct IKEv2_NONCE_PAYLOAD {
	BUF* nonce;
} IKEv2_NONCE_PAYLOAD;
// End of NONCE Payload

// NOTIFY Payload
// Notifications
#define IKEv2_NO_ERROR						0
#define IKEv2_UNSUPPORTED_CRITICAL_PAYLOAD	1
#define IKEv2_INVALID_IKE_SPI				4
#define IKEv2_INVALID_MAJOR_VERSION			5
#define IKEv2_INVALID_SYNTAX				7
#define IKEv2_INVALID_MESSAGE_ID			9
#define IKEv2_INVALID_SPI					11
#define IKEv2_NO_PROPOSAL_CHOSEN			14
#define IKEv2_INVALID_KE_PAYLOAD			17
#define IKEv2_AUTHENTICATION_FAILED			24
#define IKEv2_SINGLE_PAIR_REQUIRED			34
#define IKEv2_NO_ADDITIONAL_SAS				35
#define IKEv2_INTERNAL_ADDRESS_FAILURE		36
#define IKEv2_FAILED_CP_REQUIRED			37
#define IKEv2_TS_UNACCEPTABLE				38
#define IKEv2_INVALID_SELECTORS				39
#define IKEv2_TEMPORARY_FAILURE				43
#define IKEv2_CHILD_SA_NOT_FOUND			44

// Notify: status types
#define IKEv2_INITIAL_CONTACT				16384
#define IKEv2_SET_WINDOW_SIZE				16385
#define IKEv2_ADDITIONAL_TS_POSSIBLE		16386
#define IKEv2_IPCOMP_SUPPORTED				16387
#define IKEv2_NAT_DETECTION_SOURCE_IP		16388
#define IKEv2_NAT_DETECTION_DESTINATION_IP	16389
#define IKEv2_COOKIE						16390
#define IKEv2_USE_TRANSPORT_MODE			16391
#define IKEv2_HTTP_CERT_LOOKUP_SUPPORTED	16392
#define IKEv2_REKEY_SA						16393
#define IKEv2_ESP_TFC_PADDING_NOT_SUPPORTED	16394
#define IKEv2_NON_FIRST_FRAGMENTS_ALSO		16395

typedef struct IKEv2_NOTIFY_PAYLOAD {
	UCHAR  protocol_id;
	UCHAR  spi_size;
	USHORT notification_type;
	BUF*   spi;
	BUF*   message;
} IKEv2_NOTIFY_PAYLOAD;
// End of NOTIFY Payload

// DELETE Payload
#define IKEv2_DELETE_PROTO_IKE	1
#define IKEv2_DELETE_PROTO_AH	2
#define IKEv2_DELETE_PROTO_ESP	3

typedef struct IKEv2_DELETE_PAYLOAD {
	UCHAR protocol_id;
	UCHAR spi_size;
	USHORT num_spi;
	LIST* spi_list;
} IKEv2_DELETE_PAYLOAD;
// End of DELETE Payload

// VendorID Payload
typedef struct IKEv2_VENDOR_PAYLOAD {
	BUF* VID;
} IKEv2_VENDOR_PAYLOAD;
// End of VendorID Payload

// Traffic Selector Payload
#define IKEv2_TS_IPV4_ADDR_RANGE 7
#define IKEv2_TS_IPV6_ADDR_RANGE 8

typedef struct IKEv2_TS_PAYLOAD {
	UCHAR	TS_count;
	LIST*	selectors; // LIST of IKEv2_TRAFFIC_SELECTOR*
} IKEv2_TS_PAYLOAD;

typedef struct IKEv2_TRAFFIC_SELECTOR {
	UCHAR	type;
	UCHAR	IP_protocol_ID;
	USHORT	selector_length;
	USHORT	start_port;
	USHORT	end_port;
	BUF*	start_address;
	BUF*	end_address;
} IKEv2_TRAFFIC_SELECTOR;
// End of Traffic Selector Payload

// Authenticated & Encrypted payload
typedef struct IKEv2_SK_PAYLOAD {
	BUF* raw_data;
	LIST* decrypted_payloads;
	BUF *init_vector;
	BUF *encrypted_payloads;
	BUF *padding;
	UCHAR pad_length;
	BUF * integrity_checksum;
	UCHAR next_payload;
	UCHAR integ_len;
} IKEv2_SK_PAYLOAD;
// End of SK payload

// CONFIGURATION Payload
#define IKEv2_CP_CFG_REQUEST 1
#define IKEv2_CP_CFG_REPLY 2
#define IKEv2_CP_CFG_SET 3
#define IKEv2_CP_CFG_ACK 4

// In comment - is multi-value and supposed attribute length
#define IKEv2_INTERNAL_IP4_ADDRESS  1  // YES*  0 or 4 octets
#define IKEv2_INTERNAL_IP4_NETMASK  2  // NO    0 or 4 octets
#define IKEv2_INTERNAL_IP4_DNS      3  // YES   0 or 4 octets
#define IKEv2_INTERNAL_IP4_NBNS     4  // YES   0 or 4 octets
#define IKEv2_INTERNAL_IP4_DHCP     6  // YES   0 or 4 octets
#define IKEv2_APPLICATION_VERSION   7  // NO    0 or more
#define IKEv2_INTERNAL_IP6_ADDRESS  8  // YES*  0 or 17 octets
#define IKEv2_INTERNAL_IP6_DNS      10 // YES   0 or 16 octets
#define IKEv2_INTERNAL_IP6_DHCP     12 // YES   0 or 16 octets
#define IKEv2_INTERNAL_IP4_SUBNET   13 // YES   0 or 8 octets
#define IKEv2_SUPPORTED_ATTRIBUTES  14 // NO    Multiple of 2
#define IKEv2_INTERNAL_IP6_SUBNET   15 // YES   17 octets

typedef struct IKEv2_CP_ATTR {
	USHORT type;
	USHORT length;
	BUF *value;
} IKEv2_CP_ATTR;

typedef struct IKEv2_CP_PAYLOAD {
	UCHAR type;
	LIST *attributes; // LIST of IKEv2_CP_ATTR
} IKEv2_CP_PAYLOAD;
// End of CONFIGURATION Payload

// Extensible Authentication Protocol (EAP) payload
typedef struct IKEv2_EAP_PAYLOAD {
	UCHAR code;
	UCHAR identifier;
	USHORT length;
	UCHAR type;
	BUF* type_data;
} IKEv2_EAP_PAYLOAD;
// End of EAP

// IKE packet payload
typedef struct IKEv2_PACKET_PAYLOAD {
	UCHAR PayloadType; // Payload type
	BUF *BitArray; // Bit array

	void* data;
} IKEv2_PACKET_PAYLOAD;

typedef struct IKEv2_PACKET {
	UINT64 SPIi;			// Initiator SPI
	UINT64 SPIr;			// Responder SPI
	UCHAR ExchangeType;		// Exchange type
	UCHAR NextPayload;		// Next payload from payload list
	bool FlagResponse;		// Is it responder's packet
	bool FlagVersion;		// Packet version
	bool FlagInitiator;		// Is it initiator's packet
	UINT MessageId;			// Message ID
	LIST *PayloadList;		// Payload list of IKEv2_PACKET_PAYLOAD
	UINT MessageSize;		// Original size
	BUF* ByteMsg;			// All byte message in Big Endian 
} IKEv2_PACKET;

// Encode functions
BUF* ikev2_SA_encode(IKEv2_SA_PAYLOAD *p);
BUF* ikev2_KE_encode(IKEv2_KE_PAYLOAD *p);
BUF* ikev2_ID_encode(IKEv2_ID_PAYLOAD *p);
BUF* ikev2_cert_encode(IKEv2_CERT_PAYLOAD *p);
BUF* ikev2_cert_req_encode(IKEv2_CERTREQ_PAYLOAD *p);
BUF* ikev2_auth_encode(IKEv2_AUTH_PAYLOAD *p);
BUF* ikev2_nonce_encode(IKEv2_NONCE_PAYLOAD *p);
BUF* ikev2_notify_encode(IKEv2_NOTIFY_PAYLOAD *p);
BUF* ikev2_delete_encode(IKEv2_DELETE_PAYLOAD *p);
BUF* ikev2_vendor_encode(IKEv2_VENDOR_PAYLOAD *p);
BUF* ikev2_TS_encode(IKEv2_TS_PAYLOAD *p);
BUF* ikev2_SK_encode(IKEv2_SK_PAYLOAD *p);
BUF* ikev2_configuration_encode(IKEv2_CP_PAYLOAD *p);
BUF* ikev2_EAP_encode(IKEv2_EAP_PAYLOAD *p);

// Decode functions
UINT ikev2_SA_decode(BUF *b, IKEv2_SA_PAYLOAD *p);
UINT ikev2_KE_decode(BUF *b, IKEv2_KE_PAYLOAD *p);
UINT ikev2_ID_decode(BUF* b, IKEv2_ID_PAYLOAD *p);
UINT ikev2_auth_decode(BUF *b, IKEv2_AUTH_PAYLOAD *auth);
UINT ikev2_cert_decode(BUF *b, IKEv2_CERT_PAYLOAD *p);
UINT ikev2_cert_req_decode(BUF *b, IKEv2_CERTREQ_PAYLOAD *p);
UINT ikev2_nonce_decode(BUF *b, IKEv2_NONCE_PAYLOAD *p);
UINT ikev2_notify_decode(BUF *b, IKEv2_NOTIFY_PAYLOAD *p);
UINT ikev2_delete_decode(BUF *b, IKEv2_DELETE_PAYLOAD *p);
UINT ikev2_vendor_decode(BUF* b, IKEv2_VENDOR_PAYLOAD *p);
UINT ikev2_TS_decode(BUF* b, IKEv2_TS_PAYLOAD *p);
UINT ikev2_SK_decode(BUF *b, IKEv2_SK_PAYLOAD *p);
UINT ikev2_configuration_decode(BUF *b, IKEv2_CP_PAYLOAD *p);
UINT ikev2_EAP_decode(BUF *b, IKEv2_EAP_PAYLOAD *p);

// Free functions
void ikev2_free_SA_payload(IKEv2_SA_PAYLOAD *p);
void ikev2_free_KE_payload(IKEv2_KE_PAYLOAD *p);
void ikev2_free_ID_payload(IKEv2_ID_PAYLOAD *p);
void ikev2_free_auth_payload(IKEv2_AUTH_PAYLOAD *p);
void ikev2_free_cert_payload(IKEv2_CERT_PAYLOAD *p);
void ikev2_free_cert_req_payload(IKEv2_CERTREQ_PAYLOAD *p);
void ikev2_free_nonce_payload(IKEv2_NONCE_PAYLOAD *p);
void ikev2_free_notify_payload(IKEv2_NOTIFY_PAYLOAD *p);
void ikev2_free_delete_payload(IKEv2_DELETE_PAYLOAD *p);
void ikev2_free_vendor_payload(IKEv2_VENDOR_PAYLOAD *p);
void ikev2_free_TS_payload(IKEv2_TS_PAYLOAD *p);
void ikev2_free_SK_payload(IKEv2_SK_PAYLOAD *p);
void ikev2_free_configuration_payload(IKEv2_CP_PAYLOAD *p);
void ikev2_free_EAP_payload(IKEv2_EAP_PAYLOAD *p);
void ikev2_free_SA_transform(IKEv2_SA_TRANSFORM *t);

// Helper functions
IKEv2_SA_TRANSFORM* Ikev2CloneTransform(IKEv2_SA_TRANSFORM* other);
USHORT Ikev2GetNotificationErrorCode(USHORT notification_type);
BUF * EndianBuf(BUF *b);
void Endian(UCHAR *b, UCHAR *bb, UINT size);
void DbgPointer(char* text, void* p, UINT size);
#endif	// IPSEC_IKEv2_PACKET_H
