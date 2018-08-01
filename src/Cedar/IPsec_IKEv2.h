#ifndef IKEv2_H
#define IKEv2_H
#include "IPsec_IkePacket.h"
#include "IPsec_IKE.h"

#include "IPsec_Ikev2Packet.h"
#include "Mayaqua/MayaType.h"

#ifndef __DEBUG_SHORTEN_MACROS__
#define __DEBUG_SHORTEN_MACROS__
#define Dbg(text, ...) Debug("%s:%u %s " text "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define DbgBuf(text, buf) DbgPointer(text, buf->Buf, buf->Size)
#endif

#ifndef min
# define min(a, b) (((a) > (b)) ? (b) : (a))
#endif // min
#ifndef max
# define max(a, b) (((a) > (b)) ? (a) : (b))
#endif // max

typedef struct IKEv2_ENCR {
	UINT type;
	union {
		struct fixed_key {
			UINT* key_sizes;
			UINT key_count;
		} fixed;

		struct key_range {
			UINT min_key_len;
			UINT max_key_len;
			UINT default_key;
		} range;
	} key_info;
	UINT block_size;
	bool is_fixed;
} IKEv2_ENCR;

typedef struct IKEv2_PRF {
	UINT type;
	UINT key_size; // equal to output size
} IKEv2_PRF;

typedef struct IKEv2_INTEG {
	UINT type;
	UINT key_size;
	UINT out_size;
} IKEv2_INTEG;

typedef struct IKEv2_DH {
	UINT type;
	UINT size;
} IKEv2_DH;

typedef struct IKEv2_CRYPTO_SETTING {
	IKEv2_ENCR* encr;
	UINT key_size;
	IKEv2_PRF* prf;
	IKEv2_INTEG* integ;
	IKEv2_DH* dh;
	bool extended_esn;
} IKEv2_CRYPTO_SETTING;

#define IKEv2_ENGINE_MAX_ELEMENT 20

typedef struct IKEv2_CRYPTO_ENGINE {
	IKEv2_ENCR* ike_encr[IKEv2_ENGINE_MAX_ELEMENT];
	IKEv2_PRF* ike_prf[IKEv2_ENGINE_MAX_ELEMENT];
	IKEv2_INTEG* ike_integ[IKEv2_ENGINE_MAX_ELEMENT];
	IKEv2_DH* ike_dh[IKEv2_ENGINE_MAX_ELEMENT];
} IKEv2_CRYPTO_ENGINE;

typedef struct IKEv2_CRYPTO_KEY_DATA {
	UINT encr_key_size;
	UINT prf_key_size;
	UINT integ_key_size;

	UCHAR* sk_d;
	UCHAR* sk_ai, *sk_ar;
	UCHAR* sk_ei, *sk_er;
	UCHAR* sk_pi, *sk_pr;

	UCHAR* shared_key;
	UCHAR* IV;

	DES_KEY_VALUE *des_key_e, *des_key_d;
	DES_KEY *des3_key_e, *des3_key_d;
	AES_KEY_VALUE *aes_key_e, *aes_key_d;
} IKEv2_CRYPTO_KEY_DATA;

typedef struct IKEv2_CRYPTO_PARAM {
	IKEv2_CRYPTO_KEY_DATA* key_data;
	IKEv2_CRYPTO_SETTING* setting;
} IKEv2_CRYPTO_PARAM;

typedef struct IKEv2_CLIENT {
	IP server_ip;
	UINT server_port;

	IP client_ip;
	UINT client_port;
} IKEv2_CLIENT;

typedef struct IKEv2_SA {
	UINT64 SPIi;
	UINT64 SPIr;
	IKEv2_CRYPTO_PARAM* param;

	bool hasEstablished;
	bool isClosed;
	bool isRekeyed;

	BUF* succ_request;
	BUF* succ_response;

	BUF* nonce_i;
	BUF* nonce_r;

	IKEv2_CLIENT* client;
	struct IKEv2_IPSECSA* eap_sa;
	IKEv2_TS_PAYLOAD* TSi, *TSr;
} IKEv2_SA;

typedef struct IKEv2_IPSECSA {
	UINT SPI;
	IKEv2_CRYPTO_PARAM* param;
	IKEv2_SA* ike_sa;
	
	bool isClosed;
} IKEv2_IPSECSA;

typedef struct IKEv2_SERVER {
	LIST* clients; // LIST of IKEv2_CLIENT
	LIST* SAs; // LIST of IKEv2_SA for IKE
	LIST* ipsec_SAs; // LIST of IKEv2_SA for IPSec

	LIST* SendPacketList; // LIST of UDPPACKET
	IKEv2_CRYPTO_ENGINE* engine; // Cryptography pre-generated engine

	IKE_SERVER* ike_server; // Need to handle: ALL clents, SockEvent, Interrupts.
} IKEv2_SERVER;

typedef struct IKEv2_NOTIFY_CONTAINER {
	void* initialContact;
	void* additionalTSPossible;
	void* IPCOMPSupported;
	void* NATSourceIP;
	void* NATDestIP;
	void* cookie;
	void* useTransportMode;
	void* rekeySA;
	void* EFCPaddingNotSupported;
	void* nonFirstFragments;
} IKEv2_NOTIFY_CONTAINER;

/* SK_d - used for deriving new keys for the Child SAs.
* SK_ai, SK_ar - key to the integrity protection algorithm for auth the component messages of subsequent exchanges.
* SK_ei, SK_er - encrypting\decrypting all subsequent messages
* SK_pi, SK_pr - used when generating AUTH payload
*
* Separate SK_e and SK_a are computed for each direction
* SK_ei, SK_ai - used to protect messages from the original initiator
* SK_ar, SK_er - used to protect messages in other direction
*
* Lengths of _d, _pi, _pr MUST be the preferred key length of PRF
* PRF = Pseudo Random Function.*/

void Ikev2GetNotifications(IKEv2_NOTIFY_CONTAINER* c, LIST* payloads);
IKEv2_SERVER* NewIkev2Server(CEDAR* cedar, IPSEC_SERVER *ipsec); // global
IKEv2_CRYPTO_ENGINE* CreateIkev2CryptoEngine();
IKEv2_CLIENT* NewIkev2Client(IP* clientIP, UINT clientPort, IP* serverIP, UINT serverPort);
IKEv2_SA* Ikev2CreateSA(UINT64 SPIi, UINT64 SPIr, IKEv2_CRYPTO_SETTING* setting, IKEv2_CRYPTO_KEY_DATA* key_data);
IKEv2_IPSECSA* Ikev2CreateIPsecSA(UINT SPI, IKEv2_SA* parent_IKESA, IKEv2_CRYPTO_KEY_DATA* key_data, IKEv2_CRYPTO_SETTING* setting);

void Ikev2FreeServer(IKEv2_SERVER* server); // global
void Ikev2FreeIKESA(IKEv2_SA* sa);
void Ikev2FreeCryptoEngine(IKEv2_CRYPTO_ENGINE* engine);
void Ikev2FreeCryptoEncr(IKEv2_ENCR* encr);

void ProcessIKEv2PacketRecv(IKEv2_SERVER *ike, UDPPACKET *p); // global
//void ProcessIKEv2SAInitExchange(IKEv2_SERVER *ike, UDPPACKET *p);
//void ProcessIKEv2AuthExchange(IKEv2_SERVER *ike, UDPPACKET *p);
//void ProcessIKEv2CreateChildSAExchange(IKEv2_SERVER *ike, UDPPACKET *p);
//void ProcessIKEv2InformatinalExchange(IKEv2_SERVER *ike, UDPPACKET *p);
void ProcessIKEv2ESP(IKEv2_SERVER *ike, UDPPACKET *p, UINT SPI, IKEv2_IPSECSA* sa, UCHAR* src, UINT src_size);

void Ikev2FreePacket(IKEv2_PACKET *p);
void Ikev2FreePayloadList(LIST *payloads);
void Ikev2FreePayload(IKEv2_PACKET_PAYLOAD *p);

//int Ikev2ProcessInformatonalPacket(IKEv2_PACKET *header);

UINT64 Ikev2CreateSPI(IKEv2_SERVER* ike);
BUF* Ikev2GenerateNonce(UCHAR key_size);

BUF* Ikev2BuildPacket(IKEv2_PACKET *p);
BUF* Ikev2BuildPayloadList(LIST *pay_list);
BUF* Ikev2BuildPayload(IKEv2_PACKET_PAYLOAD *payload);

IKEv2_PACKET*
  Ikev2CreatePacket(UINT64 SPIi, UINT64 SPIr, UCHAR exchange_type, bool is_response,
      bool version, bool is_initiator, UINT msgID, LIST* payloads);

IKEv2_PACKET_PAYLOAD* Ikev2CreatePacketPayload(UCHAR type, UINT sizeofData);
IKEv2_PACKET_PAYLOAD* Ikev2CreateNotify (USHORT type, BUF* spi, BUF* message, bool contains_child_sa);
IKEv2_PACKET_PAYLOAD* Ikev2CreateKE(USHORT dh, BUF* buf);
IKEv2_PACKET_PAYLOAD* Ikev2CreateAuth(USHORT method, BUF* data);
IKEv2_PACKET_PAYLOAD* Ikev2CreateNonce(BUF* buf);
IKEv2_PACKET_PAYLOAD* Ikev2CreateID (UCHAR type, BUF* buf, bool is_responder);
IKEv2_PACKET_PAYLOAD* Ikev2CreateSK(LIST* payloads, IKEv2_CRYPTO_PARAM* cparam);
IKEv2_PACKET_PAYLOAD* Ikev2CreateEAP(UCHAR code, UCHAR id, UCHAR type, BUF* type_data);
IKEv2_PACKET_PAYLOAD* Ikev2CreateCP(IKEv2_CP_PAYLOAD *peer_conf, LIST* attributes, UCHAR cp_type);

IKEv2_PACKET* ParseIKEv2PacketHeader(UDPPACKET *p);
IKEv2_PACKET *Ikev2ParsePacket(IKEv2_PACKET* p, void *data, UINT size, IKEv2_CRYPTO_PARAM* cparam);
LIST* Ikev2ParsePayloadList(void *data, UINT size, UCHAR first_payload, UCHAR* next_last);
IKEv2_PACKET_PAYLOAD* Ikev2DecodePayload(UCHAR payload_type, BUF *buf);

bool Ikev2IsSupportedPayload(UCHAR payload_type);
LIST* Ikev2GetAllPayloadsByType(LIST* payloads, UCHAR type);
IKEv2_PACKET_PAYLOAD* Ikev2GetPayloadByType(LIST* payloads, UCHAR type, UINT index);

IKEv2_PACKET_PAYLOAD* Ikev2ChooseBestIKESA(IKEv2_SERVER* ike, IKEv2_SA_PAYLOAD* sa, IKEv2_CRYPTO_SETTING* setting, UCHAR protocol);
IKEv2_CLIENT* Ikev2GetClient(IKEv2_SERVER* server, IP* clientIP, UINT clientPort, IP* serverIP, UINT serverPort);
IKEv2_SA* Ikev2GetSABySPIAndClient(IKEv2_SERVER* server, UINT64 SPIi, UINT64 SPIr, IKEv2_CLIENT* client);
IKEv2_IPSECSA* Ikev2GetIPSECSA(IKEv2_SERVER* server, IKEv2_SA* ike_sa, UINT SPI);

BUF* Ikev2Encrypt(void* data, UINT size, IKEv2_CRYPTO_PARAM *cparam);
BUF* Ikev2Decrypt(void* data, UINT size, IKEv2_CRYPTO_PARAM *cparam);

IKEv2_CRYPTO_KEY_DATA* IKEv2GenerateKeymatForIKESA(IKEv2_CRYPTO_SETTING* setting, IKEv2_PRF* prf, BUF *nonce_i, BUF *nonce_r,
	UCHAR *shared_key, UINT key_len, UINT64 SPIi, UINT64 SPIr, void* sk_d, UINT len_sk_d, bool isInitial);

DH_CTX* Ikev2CreateDH_CTX(IKEv2_DH* dh);

IKEv2_ENCR*
  Ikev2CreateEncr(UCHAR type, bool is_fixed, UINT* key_sizes, UINT key_count, UINT min_key,
    UINT max_key, UINT default_key, UINT block_size);
IKEv2_PRF* Ikev2CreatePRF(UCHAR type, UINT key_size);
IKEv2_INTEG* Ikev2CreateInteg(UCHAR type, UINT key_size, UINT out_size);
IKEv2_DH* Ikev2CreateDH(UCHAR type, UINT size);

IKEv2_ENCR* Ikev2GetEncr(IKEv2_CRYPTO_ENGINE* engine, USHORT type);
IKEv2_PRF* Ikev2GetPRF(IKEv2_CRYPTO_ENGINE* engine, USHORT type);
IKEv2_INTEG* Ikev2GetInteg(IKEv2_CRYPTO_ENGINE* engine, USHORT type);
IKEv2_DH* Ikev2GetDH(IKEv2_CRYPTO_ENGINE* engine, USHORT type);

void* Ikev2CalcPRF(IKEv2_PRF* prf, void* key, UINT key_size, void* text, UINT text_size);
void* Ikev2CalcPRFplus(IKEv2_PRF* prf, void* key, UINT key_size, void* text, UINT text_size, UINT needed_size);
void* Ikev2CalcInteg(IKEv2_INTEG* integ, void* key, void* text, UINT text_size);

void Ikev2SendPacket(IKEv2_SERVER* s, IKEv2_CLIENT* client, IKEv2_PACKET* p, IKEv2_CRYPTO_PARAM* param);
void Ikev2SendPacketByAddress(IKEv2_SERVER* s, IP* srcIP, UINT srcPort, IP* destIP, UINT destPort, IKEv2_PACKET* p, IKEv2_CRYPTO_PARAM* param);

IKEv2_IPSECSA* Ikev2FindIPSECSA(IKEv2_SERVER* ike, UINT SPI);
#endif // IKEv2_H
