#include <assert.h>

#include "CedarPch.h"
#include "IPsec_IKEv2.h"
#include "IPsec_Ikev2Packet.h"

// An UDP packet has been received via the IPsec tunnel
void Ikev2ProcIPsecUdpPacketRecv(IKEv2_SERVER *ike, IKEv2_CLIENT *c, PKT* pkt, UCHAR *data, UINT data_size)
{
  // Validate arguments
  if (ike == NULL || c == NULL || data == NULL || data_size == 0)
  {
    return;
  }

  if (data_size <= sizeof(UDP_HEADER))
  {
    // There is no UDP header or the data is 0 bytes
    return;
  }

  UINT payload_size;
  UINT src_port, dst_port;
  UINT packet_length;

  // UDP header
  UDP_HEADER *u = (UDP_HEADER *)data;

  packet_length = Endian16(u->PacketLength);

  if (packet_length <= sizeof(UDP_HEADER))
  {
    return;
  }

  payload_size = packet_length - sizeof(UDP_HEADER);
  Dbg("Payload size = %u", payload_size);
  if (payload_size == 0)
  {
    // No data
    return;
  }

  if (data_size < (sizeof(UDP_HEADER) + payload_size))
  {
    // Data is not followed
    return;
  }

  src_port = Endian16(u->SrcPort);
  dst_port = Endian16(u->DstPort);

  UDPPACKET p;
  // A L2TP packet has been received
  Ikev2ClientManageL2TPServer(ike->ike_server, c);

  // Update Port number
  c->L2TPClientPort = src_port;

  // Pass the received packet to the L2TP server
  p.Type = 0;
  p.Data = data + sizeof(UDP_HEADER);
  p.DestPort = IPSEC_PORT_L2TP;
  Copy(&p.DstIP, &c->L2TPServerIP, sizeof(IP));
  p.Size = payload_size;
  Copy(&p.SrcIP, &c->L2TPClientIP, sizeof(IP));
  p.SrcPort = IPSEC_PORT_L2TP;

  Dbg("[IKEv2] sending IPsec UDP src: %u dst: %u of size %u", src_port, dst_port, p.Size);
  ProcL2TPPacketRecv(c->L2TP, &p);
}


void Ikev2GetNotifications(IKEv2_NOTIFY_CONTAINER* c, LIST* payloads) {
  if (c == NULL || payloads == NULL) {
    return;
  }

  Zero(c, sizeof(IKEv2_NOTIFY_CONTAINER));

  LIST* allNtf = Ikev2GetAllPayloadsByType(payloads, IKEv2_NOTIFY_PAYLOAD_T);
  if (allNtf == NULL) {
    return;
  }

  UINT ntfCount = LIST_NUM(allNtf);
  for (UINT i = 0; i < ntfCount; ++i) {
    IKEv2_NOTIFY_PAYLOAD* ntf = ((IKEv2_PACKET_PAYLOAD*)LIST_DATA(allNtf, i))->data;

    switch (ntf->notification_type) {
      case IKEv2_INITIAL_CONTACT:
        c->initialContact = ntf;
        break;
      case IKEv2_ADDITIONAL_TS_POSSIBLE:
        c->additionalTSPossible = ntf;
        break;
      case IKEv2_IPCOMP_SUPPORTED:
        c->IPCOMPSupported = ntf;
        break;
      case IKEv2_NAT_DETECTION_SOURCE_IP:
        c->NATSourceIP = ntf;
        break;
      case IKEv2_NAT_DETECTION_DESTINATION_IP:
        c->NATDestIP = ntf;
        break;
      case IKEv2_COOKIE:
        c->cookie = ntf;
        break;
      case IKEv2_USE_TRANSPORT_MODE:
        c->useTransportMode = ntf;
        break;
      case IKEv2_REKEY_SA:
        c->rekeySA = ntf;
        break;
      case IKEv2_ESP_TFC_PADDING_NOT_SUPPORTED:
        c->EFCPaddingNotSupported = ntf;
        break;
      case IKEv2_NON_FIRST_FRAGMENTS_ALSO:
        c->nonFirstFragments = ntf;
        break;
      default:
        break;
    }
  }

  ReleaseList(allNtf);
}

// Received the L2TPv3 packet via the IPsec tunnel
void Ikev2ProcL2TPv3PacketRecv(IKE_SERVER *ike, IKEv2_CLIENT *c, UCHAR *data, UINT data_size, bool is_tunnel_mode) {
  // Validate arguments
  if (ike == NULL || c == NULL || data == NULL || data_size == 0)
    return;

  UDPPACKET p;
  c->IsL2TPOnIPsecTunnelMode = is_tunnel_mode;

  Ikev2ClientManageL2TPServer(ike, c);

  // Pass the received packet to the L2TP server
  p.Type = 0;
  p.Data = data;
  p.DestPort = IPSEC_PORT_L2TPV3_VIRTUAL;
  p.Size = data_size;

  if (is_tunnel_mode)
  {
    Copy(&p.DstIP, &c->tunnelServerIP, sizeof(IP));
    Copy(&p.SrcIP, &c->tunnelClientIP, sizeof(IP));
  }
  else
  {
    Copy(&p.DstIP, &c->L2TPServerIP, sizeof(IP));
    Copy(&p.SrcIP, &c->L2TPClientIP, sizeof(IP));
  }
  p.SrcPort = IPSEC_PORT_L2TPV3_VIRTUAL;

  ProcL2TPPacketRecv(c->L2TP, &p);
}

// Manage the L2TP server that is associated with the IKE_CLIENT
void Ikev2ClientManageL2TPServer(IKE_SERVER *ike, IKEv2_CLIENT *c) {
  if (ike == NULL || c == NULL) {
    return;
  }

  if (c->L2TP == NULL) {
    UINT crypt_block_size = IKE_MAX_BLOCK_SIZE;

    if (c->CurrentIpSecSaRecv != NULL) {
      crypt_block_size = c->CurrentIpSecSaRecv->TransformSetting.Crypto->BlockSize;
    }

    c->L2TP = NewL2TPServerEx(ike->Cedar, ike, false, crypt_block_size);
    c->L2TP->IkeClient = c;

    Copy(&c->L2TPServerIP, &c->server_ip, sizeof(IP));
    Copy(&c->L2TPClientIP, &c->client_ip, sizeof(IP));

    if (c->CurrentIpSecSaRecv != NULL) {
      Format(c->L2TP->CryptName, sizeof(c->L2TP->CryptName),
             "IPsec - %s (%u bits)",
             c->CurrentIpSecSaRecv->TransformSetting.Crypto->Name,
             c->CurrentIpSecSaRecv->TransformSetting.CryptoKeySize * 8);
    }

    Dbg("[IKEv2] L2TP server started");
  }

  L2TP_SERVER* l2tp = c->L2TP;
  if (l2tp->Interrupts == NULL) {
    l2tp->Interrupts = ike->Interrupts;
  }

  if (l2tp->SockEvent == NULL) {
    SetL2TPServerSockEvent(l2tp, ike->SockEvent);
  }

  l2tp->Now = ike->Now;
}

/* IKEv2 SERVER INITIALIZATION STRUCTURES */

IKEv2_SERVER* NewIkev2Server(CEDAR* cedar, IPSEC_SERVER *ipsec) {
  IKEv2_SERVER* server = (IKEv2_SERVER*)Malloc(sizeof(IKEv2_SERVER));
  if (server == NULL) {
    Dbg("Failed to allocate memory for IKEv2_SERVER");
    return NULL;
  }
  if (cedar == NULL) Debug("cedar is null\n");
  if (ipsec == NULL) Debug("ipsec is null\n");

  server->ike_server = NewIKEServer(cedar, ipsec);
  server->clients = NewList(NULL);
  server->SAs = NewList(NULL);
  server->ipsec_SAs = NewList(NULL);
  server->SendPacketList = NewList(NULL);
  server->engine = CreateIkev2CryptoEngine();

  return server;
}

IKEv2_CRYPTO_ENGINE* CreateIkev2CryptoEngine() {
  IKEv2_CRYPTO_ENGINE* ret = ZeroMalloc(sizeof(IKEv2_CRYPTO_ENGINE));
  if (ret == NULL) {
    Dbg("Failed to allocate memory for crypto engine");
    return NULL;
  }

  IKEv2_ENCR *des, *des3, *rc5, *idea, *cast, *blowfish, *aes_cbc, *aes_ctr;
  IKEv2_PRF *hmac_md5, *hmac_sha1;
  IKEv2_INTEG *hmac_md5_96, *hmac_sha1_96, *aes_xcbc_96;
  IKEv2_DH *dh_768, *dh_1024, *dh_1536, *dh_2048, *dh_3072, *dh_4096, *dh_6144, *dh_8192;

  //Encr
  UINT aes_keys[] = { 16, 24, 32 };
  UINT des_key[] = { 8 };
  UINT des3_key[] = { 24 };
  UINT idea_key[] = { 16 };

  des = Ikev2CreateEncr(IKEv2_TRANSFORM_ID_ENCR_DES, true, des_key, sizeof(des_key) / sizeof(UINT), 0, 0, 0, 8);
  des3 = Ikev2CreateEncr(IKEv2_TRANSFORM_ID_ENCR_3DES, true, des3_key, sizeof(des3_key) / sizeof(UINT), 0, 0, 0, 8);
  rc5 = Ikev2CreateEncr(IKEv2_TRANSFORM_ID_ENCR_RC5, false, NULL, 0, 5, 255, 16, 8);
  idea = Ikev2CreateEncr(IKEv2_TRANSFORM_ID_ENCR_IDEA, true, idea_key, sizeof(idea_key) / sizeof(UINT), 0, 0, 0, 8);
  cast = Ikev2CreateEncr(IKEv2_TRANSFORM_ID_ENCR_CAST, false, NULL, 0, 5, 16, 16, 8);
  blowfish = Ikev2CreateEncr(IKEv2_TRANSFORM_ID_ENCR_BLOWFISH, false, NULL, 0, 5, 56, 16, 8);
  aes_cbc = Ikev2CreateEncr(IKEv2_TRANSFORM_ID_ENCR_AES_CBC, true, aes_keys, sizeof(aes_keys) / sizeof(UINT), 0, 0, 0, 16);
  aes_ctr = Ikev2CreateEncr(IKEv2_TRANSFORM_ID_ENCR_AES_CTR, true, aes_keys, sizeof(aes_keys) / sizeof(UINT), 0, 0, 0, 16);

  //PRF
  hmac_md5 = Ikev2CreatePRF(IKEv2_TRANSFORM_ID_PRF_HMAC_MD5, 16);
  hmac_sha1 = Ikev2CreatePRF(IKEv2_TRANSFORM_ID_PRF_HMAC_SHA1, 20);

  //Integ
  hmac_md5_96 = Ikev2CreateInteg(IKEv2_TRANSFORM_ID_AUTH_HMAC_MD5_96, 16, 12);
  hmac_sha1_96 = Ikev2CreateInteg(IKEv2_TRANSFORM_ID_AUTH_HMAC_SHA1_96, 20, 12);
  aes_xcbc_96 = Ikev2CreateInteg(IKEv2_TRANSFORM_ID_AUTH_AES_XCBC_96, 16, 12);

  //DH
  dh_768 = Ikev2CreateDH(IKEv2_TRANSFORM_ID_DH_768, 96);
  dh_1024 = Ikev2CreateDH(IKEv2_TRANSFORM_ID_DH_1024, 128);
  dh_1536 = Ikev2CreateDH(IKEv2_TRANSFORM_ID_DH_1536, 192);
  dh_2048 = Ikev2CreateDH(IKEv2_TRANSFORM_ID_DH_2048, 256);
  dh_3072 = Ikev2CreateDH(IKEv2_TRANSFORM_ID_DH_3072, 384);
  dh_4096 = Ikev2CreateDH(IKEv2_TRANSFORM_ID_DH_4096, 512);
  dh_6144 = Ikev2CreateDH(IKEv2_TRANSFORM_ID_DH_6144, 768);
  dh_8192 = Ikev2CreateDH(IKEv2_TRANSFORM_ID_DH_8192, 1024);

  ret->ike_encr[IKEv2_TRANSFORM_ID_ENCR_DES] = des;
  ret->ike_encr[IKEv2_TRANSFORM_ID_ENCR_3DES] = des3;
  ret->ike_encr[IKEv2_TRANSFORM_ID_ENCR_RC5] = rc5;
  ret->ike_encr[IKEv2_TRANSFORM_ID_ENCR_IDEA] = idea;
  ret->ike_encr[IKEv2_TRANSFORM_ID_ENCR_CAST] = cast;
  ret->ike_encr[IKEv2_TRANSFORM_ID_ENCR_BLOWFISH] = blowfish;
  ret->ike_encr[IKEv2_TRANSFORM_ID_ENCR_AES_CBC] = aes_cbc;
  ret->ike_encr[IKEv2_TRANSFORM_ID_ENCR_AES_CTR] = aes_ctr;

  ret->ike_prf[IKEv2_TRANSFORM_ID_PRF_HMAC_MD5] = hmac_md5;
  ret->ike_prf[IKEv2_TRANSFORM_ID_PRF_HMAC_SHA1] = hmac_sha1;

  ret->ike_integ[IKEv2_TRANSFORM_ID_AUTH_HMAC_MD5_96] = hmac_md5_96;
  ret->ike_integ[IKEv2_TRANSFORM_ID_AUTH_HMAC_SHA1_96] = hmac_sha1_96;
  ret->ike_integ[IKEv2_TRANSFORM_ID_AUTH_AES_XCBC_96] = aes_xcbc_96;

  ret->ike_dh[IKEv2_TRANSFORM_ID_DH_768] = dh_768;
  ret->ike_dh[IKEv2_TRANSFORM_ID_DH_1024] = dh_1024;
  ret->ike_dh[IKEv2_TRANSFORM_ID_DH_1536] = dh_1536;
  ret->ike_dh[IKEv2_TRANSFORM_ID_DH_2048] = dh_2048;
  ret->ike_dh[IKEv2_TRANSFORM_ID_DH_3072] = dh_3072;
  ret->ike_dh[IKEv2_TRANSFORM_ID_DH_4096] = dh_4096;
  ret->ike_dh[IKEv2_TRANSFORM_ID_DH_6144] = dh_6144;
  ret->ike_dh[IKEv2_TRANSFORM_ID_DH_8192] = dh_8192;

  return ret;
}

IKEv2_CLIENT* NewIkev2Client(IP* clientIP, UINT clientPort, IP* serverIP, UINT serverPort) {
  if (clientIP == NULL || serverIP == NULL) {
    return NULL;
  }

  IKEv2_CLIENT* client = ZeroMalloc(sizeof(IKEv2_CLIENT));

  CopyIP(&client->client_ip, clientIP);
  client->client_port = clientPort;

  CopyIP(&client->server_ip, serverIP);
  client->server_port = serverPort;

  return client;
}

IKEv2_SA* Ikev2CreateSA(UINT64 SPIi, UINT64 SPIr, IKEv2_CRYPTO_SETTING* setting, IKEv2_CRYPTO_KEY_DATA* key_data) {
  IKEv2_SA* SA = (IKEv2_SA*)ZeroMalloc(sizeof(IKEv2_SA));
  if (SA == NULL) {
    Dbg("Can't allocate IKEv2_SA");
    return NULL;
  }

  SA->SPIi = SPIi;
  SA->SPIr = SPIr;
  SA->param = (IKEv2_CRYPTO_PARAM*)ZeroMalloc(sizeof(IKEv2_CRYPTO_PARAM));
  if (SA->param == NULL) {
    Dbg("Can't allocate CRYPTO_PARAM");
    return NULL;
  }
  SA->param->setting = setting;
  SA->param->key_data = key_data;

  SA->client = NULL;

  SA->hasEstablished = false;
  SA->isClosed = false;
  SA->isRekeyed = false;
  SA->isClientBehindNAT = false;

  SA->succ_request = NULL;
  SA->succ_response = NULL;
  SA->nonce_i = NULL;
  SA->nonce_r = NULL;

  SA->eap_sa = NULL;
  SA->TSi = NULL;
  SA->TSr = NULL;

  return SA;
}

IKEv2_IPSECSA* Ikev2CreateIPsecSA(UINT SPI, IKEv2_SA* parent_IKESA, IKEv2_CRYPTO_KEY_DATA* key_data, IKEv2_CRYPTO_SETTING* setting) {
  if (parent_IKESA == NULL) {
    Dbg("Creating IPSECSA - parent IKESA == NULL");
    return NULL;
  }

  IKEv2_IPSECSA* ret = ZeroMalloc(sizeof(IKEv2_IPSECSA));
  ret->ike_sa = parent_IKESA;
  ret->SPI = SPI;
  ret->seqNumber = 0;
  ret->isClosed = false;
  ret->param = ZeroMalloc(sizeof(IKEv2_CRYPTO_PARAM));
  ret->param->key_data = key_data;
  ret->param->setting = setting;
  ret->client = parent_IKESA->client;

  return ret;
}

void Ikev2FreeServer(IKEv2_SERVER* server) {
  if (server == NULL) {
    return;
  }

  // Free clients?
  ReleaseList(server->clients);

  UINT ipsec_sa_count = LIST_NUM(server->ipsec_SAs);
  for (UINT i = 0; i < ipsec_sa_count; ++i) {
    Ikev2FreeIPSECSA((IKEv2_IPSECSA*)(LIST_DATA(server->ipsec_SAs, i)));
  }
  ReleaseList(server->ipsec_SAs);

  // IKE free
  UINT sa_count = LIST_NUM(server->SAs);
  for (UINT i = 0; i < sa_count; ++i) {
    Ikev2FreeIKESA((IKEv2_SA*)(LIST_DATA(server->SAs, i)));
  }
  ReleaseList(server->SAs);

  Ikev2FreeCryptoEngine(server->engine);
  FreeIKEServer(server->ike_server);
  Free(server);
}

void Ikev2FreeCryptoKeyData(IKEv2_CRYPTO_KEY_DATA* key_data) {
  Free(key_data->sk_d);
  Free(key_data->shared_key);
  key_data->shared_key = NULL;

  if (key_data->aes_key_e != NULL) {
    AesFreeKey(key_data->aes_key_e);
  }
  if (key_data->aes_key_d != NULL) {
    AesFreeKey(key_data->aes_key_d);
  }

  if (key_data->des_key_e != NULL) {
    DesFreeKeyValue(key_data->des_key_e);
  }
  if (key_data->des_key_d != NULL) {
    DesFreeKeyValue(key_data->des_key_d);
  }

  if (key_data->des3_key_e != NULL) {
    DesFreeKey(key_data->des3_key_e);
  }
  if (key_data->des3_key_d != NULL) {
    DesFreeKey(key_data->des3_key_d);
  }

  Free(key_data);
}

void Ikev2FreeCryptoParam(IKEv2_CRYPTO_PARAM* param) {
  Ikev2FreeCryptoKeyData(param->key_data);
  Free(param->setting);
  Free(param);
}

void Ikev2FreeIPSECSA(IKEv2_IPSECSA* sa) {
  if (sa == NULL) {
    return;
  }

  Dbg("Freeing CHILD_SA");
  Ikev2FreeCryptoParam(sa->param);
  Free(sa);
}

void Ikev2FreeIKESA(IKEv2_SA* sa) {
  if (sa == NULL) {
    return;
  }

  Dbg("Freeing IKE_SA");
  Ikev2FreeCryptoParam(sa->param);

  if (sa->nonce_i != NULL) {
    FreeBuf(sa->nonce_i);
  }

  if (sa->nonce_r != NULL) {
    FreeBuf(sa->nonce_r);
  }

  if (sa->succ_request != NULL) {
    FreeBuf(sa->succ_request);
  }

  if (sa->succ_response != NULL) {
    FreeBuf(sa->succ_response);
  }

  if (sa->eap_sa != NULL) {
    //ikev2_free_SA_payload(sa->eap_sa);
  }

  if (sa->TSr != NULL) {
    ikev2_free_TS_payload(sa->TSr);
  }

  if (sa->TSi != NULL) {
    ikev2_free_TS_payload(sa->TSi);
  }

  Free(sa);
}

void Ikev2FreeCryptoEngine(IKEv2_CRYPTO_ENGINE* engine) {
  if (engine == NULL) {
    return;
  }

  for (UINT i = 0; i < IKEv2_ENGINE_MAX_ELEMENT; ++i) {
    Ikev2FreeCryptoEncr(engine->ike_encr[i]);
    Free(engine->ike_prf[i]);
    Free(engine->ike_integ[i]);
    Free(engine->ike_dh[i]);
  }

  Free(engine);
}

void Ikev2FreeCryptoEncr(IKEv2_ENCR* encr) {
  if (encr != NULL) {
    if (encr->is_fixed == true) {
      Free(encr->key_info.fixed.key_sizes);
    }
    Free(encr);
    encr = NULL;
  }
}

void Ikev2FreeClient(IKEv2_CLIENT* c) {
  if (c == NULL) {
    return;
  }

  if (c->L2TP != NULL) {
    StopL2TPServer(c->L2TP, true);
    FreeL2TPServer(c->L2TP);
  }

  Free(c);
}

/* IKEv2 PACKET PROCESSING */

bool Ikev2IsSupportedPayload(UCHAR payload_type) {
  return (payload_type == IKEv2_NO_NEXT_PAYLOAD_T) ||
         ((payload_type >= IKEv2_SA_PAYLOAD_T) && (payload_type <= IKEv2_EAP_PAYLOAD_T));
}

void ProcessIKEv2PacketRecv(IKEv2_SERVER *ike, UDPPACKET *p) {
  // Validate arguments
  if (ike == NULL || p == NULL) {
    return;
  }

  IKEv2_PACKET *header = ParseIKEv2PacketHeader(p);
  if (header == NULL) {
    Dbg("Packet header is null");
    return;
  }

  Dbg("IKEv2 Exchange type: %u", header->ExchangeType);

  switch (header->ExchangeType) {
    case IKEv2_SA_INIT:
      ProcessIKEv2SAInitExchange(ike, header, p);
      break;

    case IKEv2_AUTH:
      ProcessIKEv2AuthExchange(ike, header, p);
      break;

    case IKEv2_CREATE_CHILD_SA:
      ProcessIKEv2CreateChildSAExchange(ike, header, p);
      break;

    case IKEv2_INFORMATIONAL:
      ProcessIKEv2InformatinalExchange(ike, header, p);
      break;
  }

  Ikev2FreePacket(header);
}

void ProcessIKEv2ESP(IKEv2_SERVER *ike, UDPPACKET *p, UINT spi, IKEv2_IPSECSA* ipsec_sa, UCHAR* src, UINT src_size) {
  Dbg("IKEv2 ESP init");

  UINT seq;
  UINT block_size;
  UINT hash_size;
  UCHAR *iv;
  UCHAR *hash;
  UCHAR *encrypted_payload_data;
  UINT size_of_payload_data;
  BUF *dec;

  bool update_status = false;
  bool is_tunnel_mode = true; // for now it's true

  IKEv2_CRYPTO_PARAM* param = ipsec_sa->param;
  // Get the sequence number
  if (src_size < (sizeof(UINT) * 2))
  {
    return;
  }

  seq = READ_UINT(src + sizeof(UINT));
  Dbg("Seq: %u", seq);
  //is_tunnel_mode = IsIPsecSaTunnelMode(ipsec_sa);

  IKEv2_CLIENT* c = ipsec_sa->client;

  block_size = param->setting->encr->block_size;
  hash_size = param->setting->integ->out_size;

  Dbg("Block size = %u, hash_size = %u", block_size, hash_size);
  // Get the IV
  if (src_size < (sizeof(UINT) * 2 + block_size + hash_size + block_size))
  {
    return;
  }

  // Get the hash
  hash = src + src_size - hash_size;

  // Inspect the HMAC
  void* calced_hash = Ikev2CalcInteg(ipsec_sa->param->setting->integ, ipsec_sa->param->key_data->sk_ai, src, src_size - hash_size);
  if (Cmp(calced_hash, hash, hash_size) != 0) {
    Dbg("Hashes are not same");
    Free(calced_hash);
    return;
  }

  Free(calced_hash);

  Dbg("OK, hashes are the same");
  // Get the payload data
  encrypted_payload_data = src + sizeof(UINT) * 2 + block_size;
  size_of_payload_data = src_size - hash_size - block_size - sizeof(UINT) * 2;
  DbgPointer("Encrypted data", encrypted_payload_data, size_of_payload_data);

  if (size_of_payload_data == 0 || (size_of_payload_data % block_size) != 0)
  {
    Dbg("Not enough payload data");
    // Payload data don't exist or is not a multiple of block size
    return;
  }

  Dbg("OK, decrypting");

  // Decrypt the payload data
  param->key_data->IV = src + sizeof(UINT) * 2;
  dec = Ikev2Decrypt(encrypted_payload_data, size_of_payload_data, param);
  param->key_data->IV = NULL;

  if (dec == NULL) {
    Dbg("Decrypting failed");
    return;
  }

  Dbg("Decrypting ended");
  UCHAR *dec_data = dec->Buf;
  UINT dec_size = dec->Size;
  UCHAR size_of_padding = dec_data[dec_size - 2];
  UCHAR next_header = dec_data[dec_size - 1];

  Dbg("Next header: %u", next_header);
  DbgBuf("Dec", dec);
  if ((dec_size - 2) < size_of_padding) {
    return;
  }

  Dbg("Got actual payloads");
  UINT orig_size = dec_size - 2 - size_of_padding;
  //	ipsec_sa->TotalSize += dec_size;

  if (!is_tunnel_mode) { // uncreachable (for now?)
    // Transport mode
    switch (next_header) {
      case IP_PROTO_UDP:
        Dbg("UDP");
        break;
        //			if (ike->IPsec->Services.L2TP_IPsec || ike->IPsec->Services.EtherIP_IPsec)
        //			{
        //				 // An UDP packet has been received
        //				Ikev2ProcIPsecUdpPacketRecv(ike, c, dec_data, dec_size);
        //			}
      case IPSEC_IP_PROTO_ETHERIP:
        Dbg("EtherIP");
        break;
        //			if (ike->IPsec->Services.EtherIP_IPsec)
        //			{
        //				// An EtherIP packet has been received
        //				ProcIPsecEtherIPPacketRecv(ike, c, dec_data, dec_size, false);
        //			}
      case IPSEC_IP_PROTO_L2TPV3:
        Dbg("L2TPv3");
        break;
        //			if (ike->IPsec->Services.EtherIP_IPsec)
        //			{
        //				// A L2TPv3 packet has been received
        //				ProcL2TPv3PacketRecv(ike, c, dec_data, dec_size, false);
        //			}
    }
    return;
  }
  // Tunnel Mode
  if (next_header == IKE_PROTOCOL_ID_IPV4 || next_header == IKE_PROTOCOL_ID_IPV6) {
    // Check the contents by parsing the IPv4 / IPv6 header in the case of tunnel mode
    BUF *b = NewBuf();
    static UCHAR src_mac_dummy[6] = { 0, 0, 0, 0, 0, 0, };
    static UCHAR dst_mac_dummy[6] = { 0, 0, 0, 0, 0, 0, };
    USHORT tpid = Endian16(MAC_PROTO_IPV4);

    PKT *pkt;

    WriteBuf(b, src_mac_dummy, sizeof(src_mac_dummy));
    WriteBuf(b, dst_mac_dummy, sizeof(dst_mac_dummy));
    WriteBuf(b, &tpid, sizeof(tpid));
    WriteBuf(b, dec_data, dec_size);

    // Parse
    pkt = ParsePacket(b->Buf, b->Size);
    FreeBuf(b);

    if (pkt == NULL) {
      Dbg("packet is NULL, exiting");
      // Parsing failure
      dec_data = NULL;
      dec_size = 0;
      FreePacket(pkt);
      return;
    }

    Dbg("parsing success");
    // Parsing success
    if (pkt->TypeL3 != L3_IPV4) {
      Dbg("got IPv6, skipped");
      FreePacket(pkt);
      return;
    }
    Dbg("got IPv4 packet");

    // Save the internal IP address information
    UINTToIP(&c->tunnelServerIP, pkt->L3.IPv4Header->DstIP);
    UINTToIP(&c->tunnelClientIP, pkt->L3.IPv4Header->SrcIP);
    UCHAR dststr[64];
    UCHAR srcstr[64];
    IPToStr(dststr, 64, &c->tunnelServerIP);
    IPToStr(srcstr, 64, &c->tunnelClientIP);

    Dbg("src: %s dst: %s proto: %u", srcstr, dststr, pkt->L3.IPv4Header->Protocol);
//    if (IPV4_GET_OFFSET(pkt->L3.IPv4Header) != 0) {
//      Dbg("offset >= 0, exit");
//      FreePacket(pkt);
//      return;
//    }

    Dbg("ipv4 offset is 0, continue");
//    if ((IPV4_GET_FLAGS(pkt->L3.IPv4Header) & 0x01) != 0) {
//      Dbg("bad IPv4 flags provided, exit");
//      FreePacket(pkt);
//      return;
//    }

    Dbg("ipv4 flags are ok, continue");
    switch (pkt->L3.IPv4Header->Protocol) {
      case IP_PROTO_UDP:
        Dbg("decoded from ESP: UDP");

        Ikev2ProcIPsecUdpPacketRecv(ike, c, pkt, pkt->IPv4PayloadData, pkt->IPv4PayloadSize);
//        IKEv2_IPSECSA* sa = LIST_DATA(ike->ipsec_SAs, 0);
//
//        sa->client->server_port = 500;
//        sa->client->client_port = 4500;
//        Ikev2IPsecSendUdpPacket(ike, sa, sa->client->server_port, sa->client->client_port, pkt->IPv4PayloadData, pkt->IPv4PayloadSize);
        break;
      case IPSEC_IP_PROTO_ETHERIP:
        Dbg("decoded from ESP: EtherIP");
        break;
        // EtherIP
        //if (ike->IPsec->Services.EtherIP_IPsec)
        //{
        //	// An EtherIP packet has been received
        //	ProcIPsecEtherIPPacketRecv(ike, c, pkt->IPv4PayloadData, pkt->IPv4PayloadSize, true);
        //}
      case IPSEC_IP_PROTO_L2TPV3:
        Dbg("decoded from ESP: L2TPV3");
        break;
        // L2TPv3
        //if (ike->IPsec->Services.EtherIP_IPsec)
        //{
        //	// A L2TPv3 packet has been received
        //	ProcL2TPv3PacketRecv(ike, c, pkt->IPv4PayloadData, pkt->IPv4PayloadSize, true);
        //}
      default:
        Dbg("decoded unknown protocol from ESP: %d", pkt->L3.IPv4Header->Protocol);
    }
    FreePacket(pkt);
  }

  update_status = true; // wtf
  FreeBuf(dec);
}

// Send an UDP packet via IPsec
void Ikev2IPsecSendUdpPacket(IKEv2_SERVER *ike, IKEv2_IPSECSA *sa, UINT src_port, UINT dst_port, UCHAR *data, UINT data_size) {
  UCHAR *udp;
  UINT udp_size;
  UDP_HEADER *u;

  // Validate arguments
  if (ike == NULL || sa == NULL || data == NULL || data_size == 0)
  {
    return;
  }

  // Build an UDP packet
  udp_size = sizeof(UDP_HEADER) + data_size;
  udp = Malloc(udp_size);

  // UDP header
  u = (UDP_HEADER*)udp;
  u->SrcPort = Endian16(src_port);
  u->DstPort = Endian16(dst_port);
  u->PacketLength = Endian16(udp_size);
  u->Checksum = 0;

  //Debug("IPsec UDP Send: %u -> %u %u\n", src_port, dst_port, data_size);
#ifdef	RAW_DEBUG
  IPsecIkeSendUdpForDebug(IPSEC_PORT_L2TP, 1, data, data_size);
#endif	// RAW_DEBUG

  // Payload
  Copy(udp + sizeof(UDP_HEADER), data, data_size);

  Ikev2SendPacketByIPsecSa(ike, sa, udp, udp_size, IP_PROTO_UDP);
  Free(udp);
}

// Send a packet via IPsec
void Ikev2SendPacketByIPsecSa(IKEv2_SERVER *ike, IKEv2_IPSECSA *sa, UCHAR *data, UINT data_size, UCHAR protocol_id) {
  // Validate arguments
  if (ike == NULL || sa == NULL || data == NULL || data_size == 0)
  {
    return;
  }

  if (sa->isClosed == true) {
    Dbg("Used closed IPSECSA");
    return;
  }

  //is_tunnel_mode = IsIPsecSaTunnelMode(sa);
  bool is_tunnel_mode = true;

  IKEv2_CLIENT* c = sa->client;
  if (c == NULL) {
    return;
  }

  if (!is_tunnel_mode) {
    // Send as it is in the case of transport mode
    Ikev2SendPacketByIPsecSaInner(ike, sa, data, data_size, protocol_id);
    return;
  }
  // Add an IPv4 / IPv6 header in the case of tunnel mode
  if (IsZeroIP(&c->tunnelClientIP) == false || IsZeroIP(&c->tunnelServerIP) == false)
  {
    BUF *b;
    UCHAR esp_proto_id;

    b = NewBuf();

    if (!IsIP4(&c->tunnelClientIP)) {
      Dbg("unsupported IP version");
      return;
    }
    // IPv4 header
    IPV4_HEADER h;

    IPV4_SET_VERSION(&h, 4);
    IPV4_SET_HEADER_LEN(&h, sizeof(IPV4_HEADER) / 4);

    h.VersionAndHeaderLength = 0;
    h.TypeOfService = 0;
    h.TotalLength = Endian16((USHORT)(data_size + sizeof(IPV4_HEADER)));
    h.Identification = Endian16(c->tunnelIPID++);
    h.FlagsAndFlagmentOffset[0] = h.FlagsAndFlagmentOffset[1] = 0;
    h.TimeToLive = DEFAULT_IP_TTL;
    h.Protocol = protocol_id;
    h.SrcIP = IPToUINT(&c->tunnelServerIP);
    h.DstIP = IPToUINT(&c->tunnelClientIP);
    h.Checksum = 0;
    h.Checksum = IpChecksum(&h, sizeof(IPV4_HEADER));

    esp_proto_id = IKE_PROTOCOL_ID_IPV4;

    WriteBuf(b, &h, sizeof(IPV4_HEADER));
    WriteBuf(b, data, data_size);

    Ikev2SendPacketByIPsecSaInner(ike, sa, b->Buf, b->Size, esp_proto_id);

    FreeBuf(b);
  }
}

void Ikev2SendPacketByIPsecSaInner(IKEv2_SERVER *ike, IKEv2_IPSECSA *sa, UCHAR *data, UINT data_size, UCHAR protocol_id) {
  UINT esp_size;
  UINT encrypted_payload_size;
  UCHAR *esp;
  UINT i;
  UINT size_of_padding;
  IKE_CRYPTO_PARAM cp;
  BUF *enc;
  IKEv2_CLIENT *c;
  // Validate arguments
  if (ike == NULL || sa == NULL || data == NULL || data_size == 0)
  {
    return;
  }

  c = sa->client;
  if (c == NULL)
  {
    return;
  }

  IKEv2_CRYPTO_PARAM* param = sa->param;
  UINT block_size = param->setting->encr->block_size;
  UINT hash_size = param->setting->integ->out_size;
  // Calculate the payload size after encryption
  encrypted_payload_size = data_size + 2;
  if ((encrypted_payload_size % block_size) != 0)
  {
    encrypted_payload_size = ((encrypted_payload_size / block_size) + 1) * block_size;
  }
  size_of_padding = encrypted_payload_size - data_size - 2;

  // Calculate the size of the ESP packet
  esp_size = sizeof(UINT) * 2 + block_size + encrypted_payload_size + hash_size;

  // Build the ESP packet
  esp = Malloc(esp_size + hash_size);

  // SPI
  WRITE_UINT(esp, sa->SPI);

  // Sequence number
  sa->seqNumber++;
  WRITE_UINT(esp + sizeof(UINT), sa->seqNumber);

  // Payload data
  Copy(esp + sizeof(UINT) * 2 + block_size, data, data_size);

  // Padding
  for (i = 0; i < size_of_padding; i++)
  {
    esp[sizeof(UINT) * 2 + block_size + data_size + i] = (UCHAR)(i + 1);
  }

  // Padding length
  esp[sizeof(UINT) * 2 + block_size + data_size + size_of_padding] = (UCHAR)size_of_padding;

  // Next header number
  esp[sizeof(UINT) * 2 + block_size + data_size + size_of_padding + 1] = protocol_id;

  void* IV = Ikev2CreateIV(block_size);
  Copy(esp + sizeof(UINT) * 2, IV, block_size);
  param->key_data->IV = IV;
  enc = Ikev2Encrypt(esp + sizeof(UINT) * 2 + block_size, encrypted_payload_size, param);
  param->key_data->IV = NULL;

  if (enc != NULL)
  {
    UINT server_port = c->server_port;
    UINT client_port = c->client_port;

    // Overwrite the encrypted result
    Copy(esp + sizeof(UINT) * 2 + block_size, enc->Buf, encrypted_payload_size);

    FreeBuf(enc);

    void* hmac = Ikev2CalcInteg(param->setting->integ, param->key_data->sk_ar, esp, sizeof(UINT) * 2 + block_size + encrypted_payload_size);
    Copy(esp + sizeof(UINT) * 2 + block_size + encrypted_payload_size, hmac, hash_size);
    //*(UCHAR *)(esp + sizeof(UINT) * 2 + sa->TransformSetting.Crypto->BlockSize + encrypted_payload_size) = 0xff;

    /*if (sa->TransformSetting.CapsuleMode == IKE_P2_CAPSULE_TRANSPORT ||
      sa->TransformSetting.CapsuleMode == IKE_P2_CAPSULE_TUNNEL)
    {
      server_port = client_port = IPSEC_PORT_IPSEC_ESP_RAW;
    }*/

    // Add the completed packet to the transmission list
    Ikev2SendData(ike, &c->server_ip, server_port, &c->client_ip, client_port, esp, esp_size, IKE_UDP_TYPE_ESP);
    /*IkeSendUdpPacket(ike, IKE_UDP_TYPE_ESP, &c->server_ip, server_port, &c->client_ip, client_port,
      esp, esp_size);
*/
    //sa->TotalSize += esp_size;

    //if (sa->CurrentSeqNo >= 0xf0000000)
    //{
    //	start_qm = true;
    //}

    /*if (sa->TransformSetting.LifeKilobytes != 0)
    {
      UINT64 hard_size = (UINT64)sa->TransformSetting.LifeKilobytes * (UINT64)1000;
      UINT64 soft_size = hard_size * (UINT64)2 / (UINT64)3;

      if (sa->TotalSize >= soft_size)
      {
        start_qm = true;
      }
    }

    if (start_qm)
    {
      if (sa->StartQM_FlagSet == false)
      {
        sa->StartQM_FlagSet = true;
        c->StartQuickModeAsSoon = true;
      }
    }*/
  }
  else
  {
    // Encryption failure
    Free(esp);
  }
  Free(IV);
}

bool Ikev2HasAlreadyInit(IKEv2_SERVER *ike, UINT64 SPI, UDPPACKET *p) {
  if (ike == NULL || p == NULL) {
    return true;
  }

  LIST* sas = ike->SAs;
  UINT sa_count = LIST_NUM(sas);
  for (UINT i = 0; i < sa_count; ++i) {
    IKEv2_SA* sa = (IKEv2_SA*)LIST_DATA(sas, i);
    if (sa->SPIi == SPI && sa->client != NULL) {
      IKEv2_CLIENT* c = sa->client;
      if (CmpIpAddr(&p->SrcIP, &c->client_ip) == 0 && (p->SrcPort == c->client_port)) {
        return true;
      }
    }
  }

  return false;
}

IKEv2_NOTIFY_PAYLOAD* Ikev2GetNotifyByType(LIST* payloads, USHORT type) {
  if (payloads == NULL) {
    return NULL;
  }

  UINT count = LIST_NUM(payloads);
  for (UINT i = 0; i < count; ++i) {
    IKEv2_PACKET_PAYLOAD* payload = (IKEv2_PACKET_PAYLOAD*)LIST_DATA(payloads, i);
    if (payload->PayloadType == IKEv2_NOTIFY_PAYLOAD_T && ((IKEv2_NOTIFY_PAYLOAD*)payload->data)->notification_type == type) {
      return payload->data;
    }
  }

  return NULL;
}

IKEv2_PACKET_PAYLOAD* Ikev2CreateCPReply(IKEv2_SERVER *ike, IKEv2_CP_PAYLOAD* req) {
  if (req == NULL) {
    return NULL;
  }

  IKEv2_PACKET_PAYLOAD* reply = Ikev2CreatePacketPayload(IKEv2_CP_PAYLOAD_T, sizeof(IKEv2_CP_PAYLOAD));
  if (reply == NULL) {
    return NULL;
  }

  IKEv2_CP_PAYLOAD* ret = reply->data;
  ret->type = IKEv2_CP_CFG_REPLY;
  ret->attributes = NewList(NULL);

  UINT attrCount = LIST_NUM(req->attributes);
  for (UINT i = 0; i < attrCount; ++i) {
    // For now reply only some IPv4 queries && application version
    IKEv2_CP_ATTR* attr = ((IKEv2_CP_ATTR*)LIST_DATA(req->attributes, i));

    bool ok = false;

    IKEv2_CP_ATTR* add = Malloc(sizeof(IKEv2_CP_ATTR));
    add->type = attr->type;
    add->length = 0;
    add->value = NULL;

    switch (attr->type) {
      case IKEv2_INTERNAL_IP4_ADDRESS:
        if (attr->length > 0) {
          Dbg("Using asked IP address");
          ok = true;
          add->length = attr->length;
          add->value = CloneBuf(attr->value);
          break;
        }
        ok = true;
        add->length = 4;
        //CEDAR* cedar = ike->ike_server->Cedar;
        IP ip;
        SetIP(&ip, 10, 10, 10, 10);
        add->value = NewBufFromMemory(ip.addr, 4);
        /*bool res = StrToIP(&ip, cedar->Server->DDnsClient->CurrentIPv4);
        if (res == true) {
          Dbg("OK");
          UCHAR* ipstr = ZeroMalloc(64);
          IPToStr(ipstr, 64, &ip);
          Dbg("IP got: %s", ipstr);
          add->value = NewBufFromMemory(ip.addr, 4);
        }*/
        break;
      case IKEv2_INTERNAL_IP4_NETMASK:
        ok = true;
        add->length = 4;
        IP mask;
        SetIP(&mask, 255, 255, 255, 0);
        add->value = NewBufFromMemory(mask.addr, 4);
        DbgBuf("VALUE: ", add->value);
        break;
      case IKEv2_INTERNAL_IP4_DNS:
        add->length = 4;
        IP dns;
        SetIP(&dns, 8, 8, 8, 8);
        add->value = NewBufFromMemory(dns.addr, 4);
        ok = true;
        break;
      case IKEv2_INTERNAL_IP4_NBNS:
        Dbg("Asking for NetBios Name Server, skipping");
        ok = true;
        if (attr->length > 0) {
          add->length = attr->length;
          add->value = CloneBuf(attr->value);
        }
        break;
      case IKEv2_APPLICATION_VERSION: {
        ok = true;
        char text[] = "SoftEther IKEv2";
        add->length = strlen(text);
        add->value = NewBufFromMemory(text, add->length);
      }
      case IKEv2_INTERNAL_IP4_SUBNET:
        /*add->length = 8;
        IP sip, mip;
        SetIP(&sip, 10, 10, 10, 10);
        SetIP(&mip, 255, 255, 255, 0);
        UCHAR* r = ZeroMalloc(8);
        Copy(r, sip.addr, 4);
        Copy(r + 4, mip.addr, 4);
        add->value = NewBufFromMemory(r, 8);
        Free(r);
        break;*/
      case IKEv2_INTERNAL_IP4_DHCP:
      default:
        ok = false;
        add->length = attr->length;
        if (attr->value != NULL) {
          add->value = CloneBuf(attr->value);
        }
        Dbg("Ask for unsupported CP attribute: %u", attr->type);
        break;
    }

    if (ok == true) {
      Add(ret->attributes, add);
    }
    else {
      if (add->value != NULL) {
        FreeBuf(add->value);
      }
      Free(add);
    }
  }

  IKEv2_CP_ATTR* adda = Malloc(sizeof(IKEv2_CP_ATTR));
  adda->type = IKEv2_INTERNAL_IP4_DNS;
  adda->length = 4;
  IP dns;
  SetIP(&dns, 8, 8, 4, 4);
  adda->value = NewBufFromMemory(dns.addr, 4);
  Add(ret->attributes, adda);

  return reply;
}

IKEv2_PACKET_PAYLOAD* Ikev2CreateNATNotify(UINT64 SPIi, UINT64 SPIr, IP* ip, UINT port, USHORT type) {
  IKEv2_PACKET_PAYLOAD* reply = Ikev2CreatePacketPayload(IKEv2_NOTIFY_PAYLOAD_T, sizeof(IKEv2_NOTIFY_PAYLOAD));
  if (reply == NULL) {
    return NULL;
  }

  IKEv2_NOTIFY_PAYLOAD* ret = reply->data;
  ret->spi_size = 0;
  ret->spi = NewBuf();
  ret->protocol_id = 0;
  ret->notification_type = type;

  BUF* buf = NewBuf();
  WriteBufInt64(buf, SPIi);
  WriteBufInt64(buf, SPIr);
  WriteBuf(buf, ip->addr, 4);
  WriteBufInt(buf, port);

  void* dst = ZeroMalloc(20);
  Sha1(dst, buf->Buf, buf->Size);
  ret->message = NewBufFromMemory(dst, 20);

  Free(dst);
  FreeBuf(buf);
  return reply;
}

// IKEv2 SA_INIT
void ProcessIKEv2SAInitExchange(IKEv2_SERVER *ike, IKEv2_PACKET* header, UDPPACKET *p) {
  if (ike == NULL || header == NULL || p == NULL) {
    return;
  }

  Dbg("SA_INIT started");

  IKEv2_PACKET* packet = Ikev2ParsePacket(header, p->Data, p->Size, NULL);
  if (packet == NULL) {
    Dbg("SA_INIT: can't parse packet");
    goto end;
  }

  Dbg("Packet parsed");

  UINT64 SPIi = packet->SPIi;
  if (Ikev2HasAlreadyInit(ike, SPIi, p) == true) {
    // retransmitted sa_init, exit
    Dbg("SA_INIT retransmitted");
    goto end;
  }

  IKEv2_PACKET_PAYLOAD* SAi = Ikev2GetPayloadByType(packet->PayloadList, IKEv2_SA_PAYLOAD_T, 0);
  IKEv2_PACKET_PAYLOAD* KEi = Ikev2GetPayloadByType(packet->PayloadList, IKEv2_KE_PAYLOAD_T, 0);
  IKEv2_PACKET_PAYLOAD* Ni = Ikev2GetPayloadByType(packet->PayloadList, IKEv2_NONCE_PAYLOAD_T, 0);
  IKEv2_PACKET_PAYLOAD* CPi = Ikev2GetPayloadByType(packet->PayloadList, IKEv2_CP_PAYLOAD_T, 0);

  if (SAi == NULL || KEi == NULL || Ni == NULL) {
    Dbg("Error: SAi: %p KEi: %p Ni: %p", SAi, KEi, Ni);
    goto end;
  }

  IKEv2_SA_PAYLOAD* SA = SAi->data;
  IKEv2_KE_PAYLOAD* KE = KEi->data;
  IKEv2_NONCE_PAYLOAD* nonce_i = Ni->data;
  IKEv2_CP_PAYLOAD* CP = (CPi == NULL) ? NULL : CPi->data;

  IKEv2_CRYPTO_SETTING* setting = (IKEv2_CRYPTO_SETTING*)ZeroMalloc(sizeof(IKEv2_CRYPTO_SETTING));
  IKEv2_PACKET_PAYLOAD* SAr = Ikev2ChooseBestIKESA(ike, SA, setting, IKEv2_PROPOSAL_PROTOCOL_IKE);

  if (SAr == NULL) { // All transforms are incompatible, SA not chosen
    Dbg("Responder SA cannot be constructed");

    BUF* ntfMsg = NewBuf();
    IKEv2_PACKET_PAYLOAD* notification = Ikev2CreateNotify(IKEv2_NO_PROPOSAL_CHOSEN, NULL, ntfMsg, false);
    FreeBuf(ntfMsg);

    LIST* to_send = NewListSingle(notification);
    IKEv2_PACKET* np = Ikev2CreatePacket(SPIi, 0, IKEv2_SA_INIT, true, false, false, packet->MessageId, to_send);
    Ikev2SendPacketByAddress(ike, &p->DstIP, p->DestPort, &p->SrcIP, p->SrcPort, np, NULL);

    Ikev2FreePacket(np);
    Free(setting);

    goto end;
  }

  // Not guessed DH_transform_ID in KE payload
  if (setting->dh->type != KE->DH_transform_ID) {
    Dbg("Setting->dh->type: %u KE->DH_transform_ID: %u", setting->dh->type, KE->DH_transform_ID);

    BUF* error = NewBuf();
    WriteBufShort(error, setting->dh->type);
    IKEv2_PACKET_PAYLOAD* notification = Ikev2CreateNotify(IKEv2_INVALID_KE_PAYLOAD, NULL, error, false);
    FreeBuf(error);

    LIST* to_send = NewListSingle(notification);
    IKEv2_PACKET* np = Ikev2CreatePacket(SPIi, 0, IKEv2_SA_INIT, true, false, false, packet->MessageId, to_send);
    Ikev2SendPacketByAddress(ike, &p->DstIP, p->DestPort, &p->SrcIP, p->SrcPort, np, NULL);

    Free(setting);
    Ikev2FreePayload(SAr);
    Ikev2FreePacket(np);

    goto end;
  }

  DH_CTX* dh = Ikev2CreateDH_CTX(setting->dh);
  if (dh == NULL) {
    Dbg("DH_CTX creation failure");
    Free(setting);
    Ikev2FreePayload(SAr);

    goto end;
  }

  IP myIP;
  StrToIP(&myIP, ike->ike_server->Cedar->Server->DDnsClient->CurrentIPv4);

  IKEv2_NOTIFY_CONTAINER allNtfs;
  Ikev2GetNotifications(&allNtfs, packet->PayloadList);

  IKEv2_NOTIFY_PAYLOAD* nat_source_i = allNtfs.NATSourceIP;
  IKEv2_NOTIFY_PAYLOAD* nat_dest_i = allNtfs.NATDestIP;
  bool isClientNAT = false;

  if (nat_source_i != NULL && nat_dest_i != NULL) {
    BUF* bsi = nat_source_i->message;
    BUF* bdi = nat_dest_i->message;

    DbgBuf("NAT_SOURCE_IP_I: ", bsi);
    DbgBuf("NAT_DESTINATION_IP_I: ", bdi);

    bool natted = true;
    BUF* bSrc = NewBuf();
    WriteBufInt64(bSrc, SPIi);
    WriteBufInt64(bSrc, (UINT64)0);
    WriteBuf(bSrc, p->SrcIP.addr, 4);
    WriteBufInt(bSrc, p->SrcPort);

    void* dest = ZeroMalloc(20);
    Sha1(dest, bSrc->Buf, bSrc->Size);
    DbgPointer("CALCED_NAT_SOURCE_IP", dest, 20);
    if (Cmp(dest, bsi->Buf, bsi->Size) == 0) {
      natted = false;
    }

    BUF* bDest = NewBuf();
    WriteBufInt64(bDest, SPIi);
    WriteBufInt64(bDest, (UINT64)0);
    WriteBuf(bDest, myIP.addr, 4);
    WriteBufInt(bDest, p->DestPort);

    Sha1(dest, bDest->Buf, bDest->Size);
    DbgPointer("CALCED_NAT_DESTINATION_IP", dest, 20);
    if ((natted == true) && Cmp(dest, bdi->Buf, bdi->Size) == 0) {
      natted = false;
    }

    isClientNAT = natted;
    if (isClientNAT == true) {
      Dbg("NAT behind client detected");
    }
  }

  UCHAR* shared_key = ZeroMalloc(sizeof(UCHAR) * setting->dh->size); // g ^ ir
  if (DhCompute(dh, shared_key, KE->key_data->Buf, KE->key_data->Size)) {
    UINT64 SPIr = Ikev2CreateSPI(ike);
    BUF* nonce_r = Ikev2GenerateNonce(setting->prf->key_size);

    IKEv2_CRYPTO_KEY_DATA* key_data =
        IKEv2GenerateKeymatForIKESA(setting, setting->prf, nonce_i->nonce, nonce_r, shared_key, setting->dh->size, SPIi, SPIr, NULL, 0, true);

    if (key_data == NULL) {
      Dbg("Keying material generation failed");
      Free(setting);
      Ikev2FreePayload(SAr);
      IkeDhFreeCtx(dh);
      Free(shared_key);
      FreeBuf(nonce_r);

      goto end;
    }

    IKEv2_CLIENT* client = NewIkev2Client(&p->SrcIP, p->SrcPort, &p->DstIP, p->DestPort);
    IKEv2_SA* newSA = Ikev2CreateSA(SPIi, SPIr, setting, key_data);
    newSA->client = client;
    newSA->hasEstablished = false;
    newSA->isClientBehindNAT = isClientNAT;
    newSA->nonce_i = CloneBuf(nonce_i->nonce);
    newSA->nonce_r = CloneBuf(nonce_r);
    newSA->succ_request = CloneBuf(packet->ByteMsg);

    Add(ike->clients, client);
    Add(ike->SAs, newSA);

    IKEv2_PACKET_PAYLOAD* KEr = Ikev2CreateKE(setting->dh->type, dh->MyPublicKey);
    IKEv2_PACKET_PAYLOAD* Nr = Ikev2CreateNonce(nonce_r);
    IKEv2_PACKET_PAYLOAD* NATs = Ikev2CreateNATNotify(SPIi, SPIr, &myIP, p->DestPort, IKEv2_NAT_DETECTION_SOURCE_IP);
    IKEv2_PACKET_PAYLOAD* NATd = Ikev2CreateNATNotify(SPIi, SPIr, &(p->SrcIP), p->SrcPort, IKEv2_NAT_DETECTION_DESTINATION_IP);

    LIST* send_list = NewListFast(NULL);
    Add(send_list, SAr);
    Add(send_list, KEr);
    Add(send_list, Nr);
    Add(send_list, NATs);
    Add(send_list, NATd);

    IKEv2_PACKET_PAYLOAD* cp = (CP != NULL && CP->type == IKEv2_CP_CFG_REQUEST) ? Ikev2CreateCPReply(ike, CP) : NULL;
    if (cp != NULL) {
      Add(send_list, cp);
    }

    IKEv2_PACKET* to_send = Ikev2CreatePacket(SPIi, SPIr, IKEv2_SA_INIT, true, false, false, packet->MessageId, send_list);
    client->server_port = IPSEC_PORT_IPSEC_ISAKMP; // costil
    Ikev2SendPacket(ike, client, to_send, NULL);
    newSA->succ_response = CloneBuf(to_send->ByteMsg);

    FreeBuf(nonce_r);
    Ikev2FreePacket(to_send);
  }
  else {
    Dbg("Dh compute failed");
    Free(setting);
    Ikev2FreePayload(SAr);
    Free(shared_key);
  }

  IkeDhFreeCtx(dh);

  end:
  Dbg("SA_INIT finished\n");
}

BUF* IKEv2ComputeSignedOctets(BUF* message, BUF* nonce, IKEv2_PRF* prf, void* key, UINT key_size, BUF* id) {
  if (message == NULL || nonce == NULL || prf == NULL || key == NULL || id == NULL) {
    return NULL;
  }

  void* mac = Ikev2CalcPRF(prf, key, key_size, id->Buf, id->Size);
  if (mac == NULL) {
    Dbg("SignedOctets prf calc failed");
    return NULL;
  }

  BUF* ret = NewBuf();
  WriteBufBuf(ret, message);
  WriteBufBuf(ret, nonce);
  WriteBuf(ret, mac, prf->key_size);

  Free(mac);
  return ret;
}

BUF* IKEv2CalcAuth(IKEv2_PRF* prf, void* shared_key, UINT key_size, void* text, UINT text_size, BUF* octets) {
  if (prf == NULL || shared_key == NULL || text == NULL || octets == NULL) {
    return NULL;
  }

  void* first = Ikev2CalcPRF(prf, shared_key, key_size, text, text_size);
  if (first == NULL) {
    Dbg("AUTH - first prf == NULL");
    return NULL;
  }

  void* second = Ikev2CalcPRF(prf, first, prf->key_size, octets->Buf, octets->Size);
  if (second == NULL) {
    Dbg("AUTH - second prf == NULL");
    Free(first);
    return NULL;
  }

  return NewBufFromMemory(second, prf->key_size);
}

IKEv2_CRYPTO_KEY_DATA* IKEv2CreateKeymatWithoutDHForChildSA(IKEv2_PRF* prf, void* sk_d, BUF* nonce_i, BUF* nonce_r, UINT encr_key_size, UINT integ_key_size) {
  if (prf == NULL || sk_d == NULL || nonce_i == NULL || nonce_r == NULL) {
    Dbg("prf: %p sk_d %p nonceI %p noceR %p", prf, sk_d, nonce_i, nonce_r);
    return NULL;
  }

  Dbg("Creating new keymat for childSA...");
  BUF* text = NewBuf();
  WriteBufBuf(text, nonce_i);
  WriteBufBuf(text, nonce_r);

  UINT needed_size = 2 * (encr_key_size + integ_key_size);
  Dbg("Needed size = %u", needed_size);
  UCHAR* res = Ikev2CalcPRFplus(prf, sk_d, prf->key_size, text->Buf, text->Size, needed_size);
  FreeBuf(text);

  if (res == NULL) {
    Dbg("Calc keymat in child SA failed, PRF+ returned NULL");
    return NULL;
  }

  IKEv2_CRYPTO_KEY_DATA* key_data = ZeroMalloc(sizeof(IKEv2_CRYPTO_KEY_DATA));
  key_data->encr_key_size = encr_key_size;
  key_data->integ_key_size = integ_key_size;
  key_data->IV = NULL;

  key_data->aes_key_e = key_data->aes_key_d = NULL;
  key_data->des_key_e = key_data->des_key_d = NULL;
  key_data->des3_key_e = key_data->des3_key_d = NULL;

  UINT offset = 0;
  key_data->sk_ei = res;
  offset += encr_key_size;
  if (integ_key_size > 0) {
    key_data->sk_ai = res + offset;
    offset += integ_key_size;
  }
  key_data->sk_er = res + offset;
  offset += encr_key_size;
  if (integ_key_size > 0) {
    key_data->sk_ar = res + offset;
  }

  Dbg("Keymat created, OK!");
  return key_data;
}

IKEv2_CRYPTO_KEY_DATA* IKEv2CreateKeymatWithDHForChildSA(IKEv2_PRF* prf, void* sk_d, BUF* shared_secret, BUF* nonce_i, BUF* nonce_r, UINT encr_key_size, UINT integ_key_size) {
  if (prf == NULL || sk_d == NULL || nonce_i == NULL || nonce_r == NULL) {
    Dbg("prf: %p sk_d %p nonceI %p noceR %p", prf, sk_d, nonce_i, nonce_r);
    return NULL;
  }

  Dbg("Creating new keymat for childSA...");
  BUF* text = (shared_secret == NULL) ? NewBuf() : CloneBuf(shared_secret);
  WriteBufBuf(text, nonce_i);
  WriteBufBuf(text, nonce_r);

  UINT needed_size = 2 * (encr_key_size + integ_key_size);
  Dbg("Needed size = %u", needed_size);
  UCHAR* res = Ikev2CalcPRFplus(prf, sk_d, prf->key_size, text->Buf, text->Size, needed_size);
  FreeBuf(text);

  if (res == NULL) {
    Dbg("Calc keymat in child SA failed, PRF+ returned NULL");
    return NULL;
  }

  IKEv2_CRYPTO_KEY_DATA* key_data = ZeroMalloc(sizeof(IKEv2_CRYPTO_KEY_DATA));
  key_data->encr_key_size = encr_key_size;
  key_data->integ_key_size = integ_key_size;
  key_data->sk_ei = res;
  key_data->sk_er = res + encr_key_size;
  if (integ_key_size > 0) {
    UINT offset = encr_key_size + integ_key_size;
    key_data->sk_ai = res + offset;
    offset += integ_key_size;
    key_data->sk_ar = res + offset;
  }

  Dbg("Keymat created, OK!");
  return key_data;
}

IKEv2_PACKET_PAYLOAD* Ikev2CreateTSr(IKEv2_SERVER* ike, IKEv2_TS_PAYLOAD* ask) {
  if (ike == NULL || ask == NULL) {
    return NULL;
  }

  IKEv2_PACKET_PAYLOAD* ret = Ikev2CreatePacketPayload(IKEv2_TSr_PAYLOAD_T, sizeof(IKEv2_TS_PAYLOAD));
  if (ret == NULL) {
    return NULL;
  }

  IKEv2_TS_PAYLOAD* ts = ret->data;
  ts->TS_count = 1;
  ts->selectors = NewList(NULL);
  IKEv2_TRAFFIC_SELECTOR* sel = ZeroMalloc(sizeof(IKEv2_TRAFFIC_SELECTOR));
  sel->IP_protocol_ID = 0;
  sel->type = IKEv2_TS_IPV4_ADDR_RANGE;
  sel->start_port = 0;
  sel->end_port = 65535;

  BUF* ip = NewBuf();
  IP myIP;
  StrToIP(&myIP, ike->ike_server->Cedar->Server->DDnsClient->CurrentIPv4);
  WriteBuf(ip, myIP.addr, 4);
  sel->start_address = ip;
  sel->end_address = CloneBuf(ip);

  sel->selector_length = 2 * ip->Size + 8;

  Add(ts->selectors, sel);

  return ret;
}

//SK{IDi, AUTH, SAi2, TSi, TSr}
void ProcessIKEv2AuthExchange(IKEv2_SERVER *ike, IKEv2_PACKET* header,  UDPPACKET *p) {
  if (ike == NULL || p == NULL) {
    return;
  }

  UINT64 SPIi = header->SPIi;
  UINT64 SPIr = header->SPIr;

  Dbg("Getting IKE_SA with SPIs: %u, %u", SPIi, SPIr);
  IKEv2_SA* SA = Ikev2GetSABySPIAndClient(ike, SPIi, SPIr, NULL);
  if (SA == NULL) {
    Dbg("SA not found!");
    return;
  }

  if (SA->hasEstablished == true) {
    // Auth already complete
    return;
  }

  if (SA->isClosed == true) {
    Dbg("Using closed IKE_SA, don't know what to do with it");
    return;
  }

  IKEv2_CRYPTO_PARAM* param = SA->param;
  IKEv2_PACKET* packet = Ikev2ParsePacket(header, p->Data, p->Size, param);
  if (packet == NULL) {
    Dbg("Corrupted packet, exiting SA_AUTH");
    return;
  }

  IKEv2_PACKET_PAYLOAD* pSKi = Ikev2GetPayloadByType(packet->PayloadList, IKEv2_SK_PAYLOAD_T, 0);
  if (pSKi == NULL) {
    Dbg("SK payload is not found");
    goto end;
  }

  IKEv2_SK_PAYLOAD* SKi = pSKi->data;
  LIST* payloads = SKi->decrypted_payloads;

  IKEv2_PACKET_PAYLOAD* pIDi = Ikev2GetPayloadByType(payloads, IKEv2_IDi_PAYLOAD_T, 0);
  IKEv2_PACKET_PAYLOAD* pIDr = Ikev2GetPayloadByType(payloads, IKEv2_IDr_PAYLOAD_T, 0);
  IKEv2_PACKET_PAYLOAD* pAUTHi = Ikev2GetPayloadByType(payloads, IKEv2_AUTH_PAYLOAD_T, 0);
  IKEv2_PACKET_PAYLOAD* pCPi = Ikev2GetPayloadByType(payloads, IKEv2_CP_PAYLOAD_T, 0);
  IKEv2_PACKET_PAYLOAD* pSAi = Ikev2GetPayloadByType(payloads, IKEv2_SA_PAYLOAD_T, 0);
  IKEv2_PACKET_PAYLOAD* pTSi = Ikev2GetPayloadByType(payloads, IKEv2_TSi_PAYLOAD_T, 0);
  IKEv2_PACKET_PAYLOAD* pTSr = Ikev2GetPayloadByType(payloads, IKEv2_TSr_PAYLOAD_T, 0);
  IKEv2_PACKET_PAYLOAD* pEAP = Ikev2GetPayloadByType(payloads, IKEv2_EAP_PAYLOAD_T, 0);

  IKEv2_NOTIFY_CONTAINER allNtfs;
  Ikev2GetNotifications(&allNtfs, payloads);

  IP myIP;
  StrToIP(&myIP, ike->ike_server->Cedar->Server->DDnsClient->CurrentIPv4);

  if (LIST_NUM(payloads) == 1) {
    if (pEAP != NULL) {
      Dbg("Got EAP message");
      goto end;
    }

    if (pAUTHi != NULL) {
      Dbg("Got final AUTH request");
      goto end;
    }

    Dbg("Got 1 payload, NOT EAP NOR AUTH");
    goto end;
  }

  if (!(pIDi == NULL || pSAi == NULL || pTSi == NULL || pTSr == NULL)) {
    IKEv2_ID_PAYLOAD* IDi = pIDi->data;
    IKEv2_SA_PAYLOAD* SAi = pSAi->data;
    // Skip this for now
    IKEv2_TS_PAYLOAD* TSi = pTSi->data;
    IKEv2_TS_PAYLOAD* TSr = pTSr->data;
    IKEv2_CP_PAYLOAD* CPi = (pCPi == NULL) ? NULL : pCPi->data;

    //EAP start found
    if (pAUTHi == NULL) {
      // EAP is temporally disabled with mock
      Dbg("EAP: disabled");
      /* LIST* send_list = NewList(NULL); */
      IKEv2_PACKET_PAYLOAD* mock = Ikev2CreateNotify(IKEv2_AUTHENTICATION_FAILED, NULL, NewBuf(), false);
      LIST* to_send = NewListSingle(mock);
      IKEv2_PACKET* np = Ikev2CreatePacket(SPIi, SPIr, IKEv2_AUTH, true, false, false, packet->MessageId, to_send);
      Dbg("EAP: Sending packet...");
      Ikev2SendPacketByAddress(ike, &p->DstIP, p->DestPort, &p->SrcIP, p->SrcPort, np, param);
      return;
      // EAP mock end

      Dbg("EAP found, let's fuck");

      IKEv2_ID_PAYLOAD* IDi = pIDi->data;
      Dbg("EAP: IDi type: %u", IDi->ID_type);
      DbgBuf("EAP: IDi", IDi->data);
      IKEv2_ID_PAYLOAD* IDr = (pIDr == NULL) ? NULL : pIDr->data;
      IKEv2_SA_PAYLOAD* SAi = pSAi->data;
      // Skip this for now
      IKEv2_TS_PAYLOAD* TSi = pTSi->data;
      IKEv2_TS_PAYLOAD* TSr = pTSr->data;

      // Comment this for now
      //SA->eap_sa = SAi;
      SA->TSi = TSi;
      SA->TSr = TSr;

      BUF* ip_data = NULL;
      if (IDr == NULL) {
        Dbg("EAP: Creating new IDr");
        IP* myIP = &(SA->client->server_ip);
        ip_data = NewBufFromMemory(myIP->addr, 4);
        DbgBuf("EAP: ip_data", ip_data);
        pIDr = Ikev2CreateID(IKEv2_DH_ID_IPV4_ADDR, ip_data, true);
      }
      else {
        Dbg("EAP: Using existing IDr");
        ip_data = IDr->data;
      }

      BUF* signed_octets_r = IKEv2ComputeSignedOctets(SA->succ_response, SA->nonce_i, param->setting->prf, param->key_data->sk_pr, param->setting->prf->key_size, ip_data);
      if (signed_octets_r != NULL) {
        Dbg("EAP: Responder signed octets calculated");
        BUF* auth_r_calced = IKEv2CalcAuth(param->setting->prf, ike->ike_server->Secret, strlen(ike->ike_server->Secret), "Key Pad for IKEv2", 17, signed_octets_r);
        if (auth_r_calced != NULL) {
          Dbg("AUTH_r calced");
          Dbg("EAP: Auth field calculated, size=%u", auth_r_calced->Size);
          IKEv2_PACKET_PAYLOAD* auth_r = Ikev2CreateAuth(IKEv2_AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE, auth_r_calced);

          BUF* info = NewBuf();
          IKEv2_PACKET_PAYLOAD* eap = Ikev2CreateEAP(1, 0, 0, info);
          FreeBuf(info);

          LIST* send_list = NewList(NULL);
          Add(send_list, pIDr);
          Add(send_list, auth_r);
          Add(send_list, eap);

          Dbg("EAP: Creating SK payload with payload count=%u", send_list->num_item);
          IKEv2_PACKET_PAYLOAD* sk = Ikev2CreateSK(send_list, param);
          ((IKEv2_SK_PAYLOAD*)sk->data)->integ_len = param->setting->integ->out_size;
          Dbg("EAP: SK payload created!");

          Dbg("EAP: Freeing send_list");
          //Ikev2FreePayload(auth_r);
          //Free(auth_r);
          Dbg("");
          if (IDr == NULL) {
            Dbg("Freeing pIDr");
            Ikev2FreePayload(pIDr);
            Dbg("");
            Free(pIDr);
          }

          //Ikev2FreePayload(eap);
          //Free(eap);
          ReleaseList(send_list);

          LIST* sk_list = NewList(NULL);
          Add(sk_list, sk);
          Dbg("EAP: Creating packet for transmission...");
          IKEv2_PACKET* to_send = Ikev2CreatePacket(SPIi, SPIr, IKEv2_AUTH, true, false, false, packet->MessageId, sk_list);
          Dbg("EAP: Sending packet...");
          Ikev2SendPacketByAddress(ike, &p->DstIP, p->DestPort, &p->SrcIP, p->SrcPort, to_send, param);
          Dbg("EAP: Packet sent, size=%u, OK\nReleasing all structures...", to_send->MessageSize);
          Dbg("Freeing packet to_send with payload count %u", LIST_NUM(to_send->PayloadList));
          /* Ikev2FreePacket(to_send); */
          //Ikev2FreePayload(sk);
          /* Dbg(""); */


          //ReleaseList(sk_list);
          Dbg("");
          FreeBuf(auth_r_calced);
        }
      }
    }
    else {
      // Typical response
      IKEv2_ID_PAYLOAD* IDr = (pIDr == NULL) ? NULL : pIDr->data;
      IKEv2_AUTH_PAYLOAD* AUTHi = pAUTHi->data;

      Dbg("IDi: type %u, size %u", IDi->ID_type, IDi->data->Size);
      DbgBuf("IDi: ", IDi->data);

      if (AUTHi->auth_method != IKEv2_AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE) {
        Dbg("Auth method = %u is not supported, exiting", AUTHi->auth_method);
        goto end;
      }

      //CHECK IF INITIATOR AUTH IS OK
      BUF* id_data = ikev2_ID_encode(IDi);
      BUF* signed_octets_i = IKEv2ComputeSignedOctets(SA->succ_request, SA->nonce_r, param->setting->prf, param->key_data->sk_pi, param->setting->prf->key_size, id_data);
      FreeBuf(id_data);

      if (signed_octets_i == NULL) {
        Dbg("Initiator signed octets == NULL");
        goto end;
      }

      BUF* auth_i_integ = AUTHi->data;
      BUF* auth_i_calced = IKEv2CalcAuth(param->setting->prf, ike->ike_server->Secret, strlen(ike->ike_server->Secret), "Key Pad for IKEv2", 17, signed_octets_i);
      FreeBuf(signed_octets_i);

      if (auth_i_calced == NULL || auth_i_calced->Size != auth_i_integ->Size ||
          (Cmp(auth_i_calced->Buf, auth_i_integ->Buf, auth_i_integ->Size) != 0)) {
        Dbg("Calced AUTH value doesn't match with AUTH_I");
        if (auth_i_calced != NULL) {
          FreeBuf(auth_i_calced);
        }

        goto end;
      }

      //It's ok, create new auth
      FreeBuf(auth_i_calced);

      IKEv2_CRYPTO_SETTING* ipsec_setting = ZeroMalloc(sizeof(IKEv2_CRYPTO_SETTING));
      IKEv2_PACKET_PAYLOAD* pSAr = Ikev2ChooseBestIKESA(ike, SAi, ipsec_setting, IKEv2_PROPOSAL_PROTOCOL_ESP);
      if (pSAr == NULL) {
        // Maybe should reply with Informational msg
        Dbg("IPSEC_SA is not chosen");
        Free(ipsec_setting);

        goto end;
      }

      Dbg("Choosen IPSEC_SA encr = %u with key_size = %u", ipsec_setting->encr->type, ipsec_setting->key_size);
      IKEv2_CRYPTO_KEY_DATA* keymat = IKEv2CreateKeymatWithoutDHForChildSA(param->setting->prf, param->key_data->sk_d, SA->nonce_i, SA->nonce_r,
                                                                           ipsec_setting->key_size, (ipsec_setting->integ == NULL) ? 0 : ipsec_setting->integ->key_size);

      if (keymat == NULL) {
        Dbg("Keymat is NULL");
        Free(ipsec_setting);
        Ikev2FreePayload(pSAr);

        goto end;
      }

      if (IDr == NULL) {
        Dbg("Creating new IDr");
        BUF* ip_data = NewBufFromMemory(myIP.addr, 4);
        pIDr = Ikev2CreateID(IKEv2_DH_ID_IPV4_ADDR, ip_data, true); // Because it's NULL
        FreeBuf(ip_data);
      }

      BUF* id_data_r = ikev2_ID_encode(pIDr->data);
      BUF* signed_octets_r = IKEv2ComputeSignedOctets(SA->succ_response, SA->nonce_i, param->setting->prf, param->key_data->sk_pr, param->setting->prf->key_size, id_data_r);
      FreeBuf(id_data_r);

      if (signed_octets_r == NULL) {
        Dbg("Responder signed octets == NULL");
        Free(ipsec_setting);
        Ikev2FreePayload(pSAr);
        Ikev2FreeCryptoKeyData(keymat);
        if (IDr == NULL) {
          Ikev2FreePayload(pIDr);
        }

        goto end;
      }

      BUF* auth_r_calced = IKEv2CalcAuth(param->setting->prf, ike->ike_server->Secret, strlen(ike->ike_server->Secret), "Key Pad for IKEv2", 17, signed_octets_r);
      FreeBuf(signed_octets_r);

      if (auth_r_calced == NULL) {
        Dbg("Calced responder AUTH == NULL");
        Free(ipsec_setting);
        Ikev2FreePayload(pSAr);
        Ikev2FreeCryptoKeyData(keymat);
        if (IDr == NULL) {
          Ikev2FreePayload(pIDr);
        }

        goto end;
      }

      IKEv2_SA_PAYLOAD* retSA = pSAr->data;
      UINT retSASPI = ReadBufInt((((IKEv2_SA_PROPOSAL*)(LIST_DATA(retSA->proposals, 0)))->SPI));
      IKEv2_IPSECSA* ipsec_newSA = Ikev2CreateIPsecSA(retSASPI, SA, keymat, ipsec_setting);
      Add(ike->ipsec_SAs, ipsec_newSA);
      SA->hasEstablished = true;

      IKEv2_PACKET_PAYLOAD* auth_r = Ikev2CreateAuth(IKEv2_AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE, auth_r_calced);
      FreeBuf(auth_r_calced);

      LIST* send_list = NewListFast(NULL);
      Add(send_list, pIDr);
      Add(send_list, auth_r);

      IKEv2_PACKET_PAYLOAD* cp = (CPi->type == IKEv2_CP_CFG_REQUEST) ? Ikev2CreateCPReply(ike, CPi) : NULL;
      if (cp != NULL) {
        Add(send_list, cp);
      }

      Add(send_list, pSAr);

      IKEv2_PACKET_PAYLOAD* newTSi = Ikev2CreateTSr(ike, TSr);
      newTSi->PayloadType = IKEv2_TSi_PAYLOAD_T;
      IKEv2_TRAFFIC_SELECTOR* seli = LIST_DATA(((IKEv2_TS_PAYLOAD*)(newTSi->data))->selectors, 0);
      IP sip;
      SetIP(&sip, 10, 10, 10, 10);
      seli->start_address = NewBufFromMemory(sip.addr, 4);
      seli->end_address = NewBufFromMemory(sip.addr, 4);
      Add(send_list, newTSi);

      IKEv2_PACKET_PAYLOAD* newTSr = Ikev2CreateTSr(ike, TSr);
      IKEv2_TRAFFIC_SELECTOR* sel = LIST_DATA(((IKEv2_TS_PAYLOAD*)(newTSr->data))->selectors, 0);
      IP rip;
      SetIP(&rip, 0, 0, 0, 0);
      sel->start_address = NewBufFromMemory(rip.addr, 4);

      SetIP(&rip, 255, 255, 255, 255);
      sel->end_address = NewBufFromMemory(rip.addr, 4);
      Add(send_list, newTSr);

      BUF* tfcMsg = NewBuf();
      IKEv2_PACKET_PAYLOAD* noTFC = Ikev2CreateNotify(IKEv2_ESP_TFC_PADDING_NOT_SUPPORTED, NULL, tfcMsg, false);
      FreeBuf(tfcMsg);
      Add(send_list, noTFC);

      Dbg("Creating SK payload with payload count == %u", LIST_NUM(send_list));
      IKEv2_PACKET_PAYLOAD* sk = Ikev2CreateSK(send_list, param);

      LIST* sk_list = NewListSingle(sk);
      IKEv2_PACKET* to_send = Ikev2CreatePacket(SPIi, SPIr, IKEv2_AUTH, true, false, false, packet->MessageId, sk_list);
      UINT port = IPSEC_PORT_IPSEC_ISAKMP;
      if (SA->isClientBehindNAT == true) {
        Dbg("Sending packet through NAT");
        port = IPSEC_PORT_IPSEC_ESP_UDP;
      }
      Ikev2SendPacketByAddress(ike, &p->DstIP, port, &p->SrcIP, p->SrcPort, to_send, param);

      Ikev2FreePacket(to_send);

      ReleaseList(send_list);
      Ikev2FreePayload(auth_r);
      if (IDr == NULL) {
        Dbg("IDr is null");
        Ikev2FreePayload(pIDr);
      }
      if (cp != NULL) {
        Ikev2FreePayload(cp);
      }
      Ikev2FreePayload(newTSi);
      Ikev2FreePayload(newTSr);
      Ikev2FreePayload(noTFC);
    }
  }

  end:
  Dbg("SA_AUTH: exit");
}

void ProcessIKEv2CreateChildSAExchange(IKEv2_SERVER *ike, IKEv2_PACKET* header, UDPPACKET *p) {
  if (ike == NULL || p == NULL) {
    Dbg("Null args in CREATE_CHILD_SA");
    return;
  }

  Dbg("Inside CREATE_CHILD_SA");

  UINT64 SPIi = header->SPIi;
  UINT64 SPIr = header->SPIr;

  Dbg("Got IKE_SA with SPIs: %u, %u", SPIi, SPIr);
  IKEv2_SA* ikeSA = Ikev2GetSABySPIAndClient(ike, SPIi, SPIr, NULL);
  if (ikeSA == NULL) {
    Dbg("IKE_SA not found!");
    return;
  }

  if (ikeSA->isClosed == true) {
    Dbg("Using closed IKE_SA, don't respond to it");
    return;
  }

  IKEv2_CRYPTO_PARAM* param = ikeSA->param;

  IKEv2_PACKET* packet = Ikev2ParsePacket(header, p->Data, p->Size, ikeSA->param);
  if (packet == NULL) {
    Dbg("Corrupted packet, exiting CREATE_CHILD_SA");
    return;
  }

  IKEv2_PACKET_PAYLOAD* pSKi = Ikev2GetPayloadByType(packet->PayloadList, IKEv2_SK_PAYLOAD_T, 0);
  if (pSKi != NULL) {
    IKEv2_SK_PAYLOAD* sk = pSKi->data;
    LIST* payloads = sk->decrypted_payloads;

    IKEv2_PACKET_PAYLOAD* pSA = Ikev2GetPayloadByType(payloads, IKEv2_SA_PAYLOAD_T, 0);
    IKEv2_PACKET_PAYLOAD* pNonce = Ikev2GetPayloadByType(payloads, IKEv2_NONCE_PAYLOAD_T, 0);
    IKEv2_PACKET_PAYLOAD* pKE = Ikev2GetPayloadByType(payloads, IKEv2_KE_PAYLOAD_T, 0);
    // Traffic selectors are not saved anywhere for now
    IKEv2_PACKET_PAYLOAD* pTSi = Ikev2GetPayloadByType(payloads, IKEv2_TSi_PAYLOAD_T, 0);
    IKEv2_PACKET_PAYLOAD* pTSr = Ikev2GetPayloadByType(payloads, IKEv2_TSr_PAYLOAD_T, 0);

    IKEv2_NOTIFY_PAYLOAD* rekeyNotify = Ikev2GetNotifyByType(payloads, IKEv2_REKEY_SA);
    bool is_rekey_child = rekeyNotify != NULL;

    if (pSA == NULL || pNonce == NULL) {
      Dbg("CREATE_CHILD_SA: not found SA or Nonce payloads");
      goto end;
    }

    IKEv2_SA_PAYLOAD* SA = pSA->data;
    IKEv2_NONCE_PAYLOAD* nonce = pNonce->data;
    IKEv2_KE_PAYLOAD* KE = (pKE == NULL) ? NULL : pKE->data;

    if (pTSi != NULL && pTSr != NULL) {
      if (is_rekey_child == true) {
        Dbg("CREATE_CHILD_SA: rekeying child SA");
      }
      else {
        Dbg("CREATE_CHILD_SA: creating new child SA");
      }

      IKEv2_CRYPTO_SETTING* newSetting = ZeroMalloc(sizeof(IKEv2_CRYPTO_SETTING));
      IKEv2_PACKET_PAYLOAD* chosenSA = Ikev2ChooseBestIKESA(ike, SA, newSetting, IKEv2_PROPOSAL_PROTOCOL_ESP);
      if (chosenSA == NULL) {
        Dbg("SA is not chosen");
        Free(newSetting);
        goto end;
      }

      IKEv2_SA_PAYLOAD* SAr = (IKEv2_SA_PAYLOAD*)(chosenSA->data);
      UCHAR* shared_secret = NULL;
      DH_CTX* dh = NULL;
      if (KE != NULL) {
        Dbg("KE payload != NULL, calculating new shared_secret");
        if (newSetting->dh->type != KE->DH_transform_ID) {
          Dbg("DH_transform_ID didn't guessed");
          Free(newSetting);
          Ikev2FreePayload(chosenSA);
          goto end;
        }

        dh = Ikev2CreateDH_CTX(newSetting->dh);
        if (dh == NULL) {
          Dbg("DH_CTX creation failure");
          Free(newSetting);
          Ikev2FreePayload(chosenSA);
          goto end;
        }

        shared_secret = ZeroMalloc(sizeof(UCHAR) * newSetting->dh->size); // g ^ ir
        Dbg("key data size: %u", KE->key_data->Size);
        if (!DhCompute(dh, shared_secret, KE->key_data->Buf, KE->key_data->Size)) {
          Dbg("Dh compute failed");
          Free(newSetting);
          Ikev2FreePayload(chosenSA);
          Free(shared_secret);
          goto end;
        }
      }

      IKEv2_PRF* curPrf = (newSetting->prf == NULL) ? param->setting->prf : newSetting->prf;
      BUF* nonce_r = Ikev2GenerateNonce(curPrf->key_size);
      IKEv2_CRYPTO_KEY_DATA* key_data = (shared_secret == NULL) ?
                                        IKEv2CreateKeymatWithoutDHForChildSA(curPrf, param->key_data->sk_d, nonce, nonce_r, newSetting->key_size, newSetting->integ->key_size) :
                                        IKEv2CreateKeymatWithDHForChildSA(curPrf, param->key_data->sk_d, shared_secret, nonce, nonce_r, newSetting->key_size, newSetting->integ->key_size);

      if (key_data == NULL) {
        Dbg("Key_data == NULL");
        Free(newSetting);
        Ikev2FreePayload(chosenSA);
        if (shared_secret != NULL) {
          Free(shared_secret);
        }
        if (dh != NULL) {
          IkeDhFreeCtx(dh);
        }
        FreeBuf(nonce_r);
        goto end;
      }

      Dbg("Key_data is not null");
      IKEv2_PACKET_PAYLOAD* KEr = (KE == NULL) ? NULL : Ikev2CreateKE(newSetting->dh->type, dh->MyPublicKey);
      IKEv2_PACKET_PAYLOAD* Nr = Ikev2CreateNonce(nonce_r);

      LIST* send_list = NewListFast(NULL);
      Add(send_list, chosenSA);
      if (KEr != NULL) {
        Add(send_list, KEr);
      }
      Add(send_list, Nr);
      Add(send_list, pTSi);
      Add(send_list, pTSr);

      IKEv2_PACKET_PAYLOAD* sk = Ikev2CreateSK(send_list, param);
      LIST* sk_list = NewListSingle(sk);

      IKEv2_PACKET* to_send = Ikev2CreatePacket(SPIi, SPIr, IKEv2_CREATE_CHILD_SA, true, false, false, packet->MessageId, sk_list);
      UINT port = IPSEC_PORT_IPSEC_ISAKMP;
      if (ikeSA->isClientBehindNAT == true) {
        Dbg("Sending packet through NAT");
        port = IPSEC_PORT_IPSEC_ESP_UDP;
      }
      Ikev2SendPacketByAddress(ike, &p->DstIP, port, &p->SrcIP, p->SrcPort, to_send, ikeSA->param);

      UINT newSPI = ReadBufInt((((IKEv2_SA_PROPOSAL*)(LIST_DATA(SAr->proposals, 0)))->SPI));
      Dbg("New SPI == %u", newSPI);
      if (is_rekey_child) {
        Dbg("Inside rekeying child");
        UINT childSPI = ReadBufInt(rekeyNotify->spi);
        Dbg("Child SPI searching == %u", childSPI);

        IKEv2_IPSECSA* child = NULL;
        UINT count = LIST_NUM(ike->ipsec_SAs);
        for (int i = 0; i < count; ++i) {
          IKEv2_IPSECSA* cur = (IKEv2_IPSECSA*)LIST_DATA(ike->ipsec_SAs, i);
          if (cur->SPI == childSPI) {
            child = cur;
            break;
          }
        }

        if (child == NULL) {
          Dbg("CHILD_SA with SPI == %u not found", childSPI);

          Free(newSetting);
          if (shared_secret != NULL) {
            Free(shared_secret);
          }

          goto free_end;
        }

        Dbg("Child is not null, adding new CHILD_SA to list");

        child->isClosed = true;
        IKEv2_IPSECSA* newChild = Ikev2CreateIPsecSA(newSPI, ikeSA, key_data, newSetting);
        Add(ike->ipsec_SAs, newChild);
      }
      else {
        Dbg("Creating & adding new ipsec_sa");
        IKEv2_IPSECSA* ipsec_newSA = Ikev2CreateIPsecSA(newSPI, ikeSA, key_data, newSetting);
        Add(ike->ipsec_SAs, ipsec_newSA);
      }

      free_end:
      Dbg("Freeing data structures");
      Ikev2FreePayload(chosenSA);
      FreeBuf(nonce_r);
      if (dh != NULL) {
        IkeDhFreeCtx(dh);
      }

      Ikev2FreePacket(to_send);
      ReleaseList(send_list);
      if (KEr != NULL) {
        Ikev2FreePayload(KEr);
      }
      Ikev2FreePayload(Nr);
    }
    else if (pTSi == NULL && pTSr == NULL) {
      if (pKE == NULL) {
        Dbg("CREATE_CHILD_SA: while rekeying IKE_SA KE payload is not present");
        goto end;
      }

      Dbg("CREATE_CHILD_SA: rekeying IKE_SA started");
      IKEv2_CRYPTO_SETTING* newSetting = ZeroMalloc(sizeof(IKEv2_CRYPTO_SETTING));
      IKEv2_PACKET_PAYLOAD* chosenSA = Ikev2ChooseBestIKESA(ike, SA, newSetting, IKEv2_PROPOSAL_PROTOCOL_IKE);
      if (chosenSA == NULL) {
        Dbg("SA is not chosen");
        Free(newSetting);
        goto end;
      }

      if (newSetting->dh->type != KE->DH_transform_ID) {
        Dbg("DH_transform_ID didn't guessed");
        Free(newSetting);
        Ikev2FreePayload(chosenSA);
        goto end;
      }

      IKEv2_SA_PAYLOAD* newSA = ((IKEv2_SA_PAYLOAD*)chosenSA->data);
      DH_CTX* dh = Ikev2CreateDH_CTX(newSetting->dh);
      if (dh == NULL) {
        Dbg("DH_CTX creation failure");
        Free(newSetting);
        Ikev2FreePayload(chosenSA);
      }
      else {
        UCHAR* shared_key = ZeroMalloc(sizeof(UCHAR) * newSetting->dh->size); // g ^ ir
        if (DhCompute(dh, shared_key, KE->key_data->Buf, KE->key_data->Size)) {
          IKEv2_SA_PROPOSAL* prop = ((IKEv2_SA_PROPOSAL*)LIST_DATA(newSA->proposals, 0));
          UINT64 newSPIi = ReadBufInt64(prop->SPI);
          UINT64 newSPIr = Ikev2CreateSPI(ike);
          BUF* nonce_r = Ikev2GenerateNonce(newSetting->prf->key_size);

          IKEv2_CRYPTO_KEY_DATA* key_data =
              IKEv2GenerateKeymatForIKESA(newSetting, param->setting->prf, nonce->nonce, nonce_r, shared_key,
                                          newSetting->dh->size, newSPIi, newSPIr, param->key_data->sk_d, param->key_data->prf_key_size, false);

          if (key_data == NULL) {
            Dbg("Keying material generation failed");
            Free(newSetting);
            Ikev2FreePayload(chosenSA);
            IkeDhFreeCtx(dh);
            Free(shared_key);
            FreeBuf(nonce_r);
            goto end;
          }

          IKEv2_PACKET_PAYLOAD* KEr = Ikev2CreateKE(newSetting->dh->type, dh->MyPublicKey);
          IKEv2_PACKET_PAYLOAD* Nr = Ikev2CreateNonce(nonce_r);

          FreeBuf(prop->SPI);
          prop->SPI = NewBuf();
          WriteBufInt64(prop->SPI, newSPIr);

          LIST* send_list = NewListFast(NULL);
          Add(send_list, chosenSA);
          Add(send_list, KEr);
          Add(send_list, Nr);

          IKEv2_PACKET_PAYLOAD* sk = Ikev2CreateSK(send_list, param);
          LIST* sk_list = NewListSingle(sk);

          IKEv2_PACKET* to_send = Ikev2CreatePacket(SPIi, SPIr, IKEv2_CREATE_CHILD_SA, true, false, false, packet->MessageId, sk_list);
          UINT port = IPSEC_PORT_IPSEC_ISAKMP;
          if (ikeSA->isClientBehindNAT == true) {
            Dbg("Sending packet through NAT");
            port = IPSEC_PORT_IPSEC_ESP_UDP;
          }
          Ikev2SendPacketByAddress(ike, &p->DstIP, port, &p->SrcIP, p->SrcPort, to_send, ikeSA->param);

          ikeSA->isClosed = true;
          ikeSA->isRekeyed = true;

          Dbg("Creating new SA with SPIi %u, SPIr %u", newSPIi, newSPIr);
          IKEv2_SA* newSA = Ikev2CreateSA(newSPIi, newSPIr, newSetting, key_data);
          newSA->client = ikeSA->client;
          newSA->hasEstablished = true;
          newSA->succ_request = CloneBuf(ikeSA->succ_request);
          newSA->succ_response = CloneBuf(ikeSA->succ_response);
          newSA->nonce_i = CloneBuf(ikeSA->nonce_i);
          newSA->nonce_r = CloneBuf(ikeSA->nonce_r);

          LockList(ike->ipsec_SAs);
          UINT childSACount = LIST_NUM(ike->ipsec_SAs);
          for (UINT i = 0; i < childSACount; ++i) {
            IKEv2_IPSECSA* childSA = (IKEv2_IPSECSA*)LIST_DATA(ike->ipsec_SAs, i);
            if (childSA->ike_sa == ikeSA) {
              childSA->ike_sa = newSA;
            }
          }
          UnlockList(ike->ipsec_SAs);
          // TODO: problem with TSi/r, need to resolve

          Add(ike->SAs, newSA);

          FreeBuf(nonce_r);
          Ikev2FreePayload(chosenSA);
          Ikev2FreePayload(KEr);
          Ikev2FreePayload(Nr);
          ReleaseList(send_list);
          Ikev2FreePacket(to_send);
        }
        else {
          Dbg("Dh compute failed");
          Free(newSetting);
          Ikev2FreePayload(chosenSA);
          Free(shared_key);
        }

        IkeDhFreeCtx(dh);
      }

      goto end;
    }
    else {
      Dbg("CREATE_CHILD_SA: error, TSi && TSr are not synchronously present");
    }
  }

  end:
  Dbg("Exit from CREATE_CHILD_SA");
}

// Parse the IKEv2 packet header
IKEv2_PACKET* ParseIKEv2PacketHeader(UDPPACKET *udp) {
  if (udp == NULL || (udp->Size < sizeof(IKEv2_HEADER))) {
    return NULL;
  }

  IKEv2_HEADER *h = (IKEv2_HEADER*)udp->Data;

  if (Endian32(h->message_length) < udp->Size) {
    Dbg("Packet size %u is too small, want %u bytes", udp->Size, Endian32(h->message_length));
    return NULL;
  }

  IKEv2_PACKET* p = (IKEv2_PACKET*)ZeroMalloc(sizeof(IKEv2_PACKET));

  p->SPIi = Endian64(h->init_SPI);
  p->SPIr = Endian64(h->resp_SPI);

  p->ExchangeType = h->exchange_type;
  p->NextPayload = h->next_payload;
  p->FlagResponse = (h->flags & IKEv2_RESPONSE_FLAG) ? true : false;
  p->FlagVersion = (h->flags & IKEv2_VERSION_FLAG) ? true : false;
  p->FlagInitiator = (h->flags & IKEv2_INITIATOR_FLAG) ? true : false;
  p->MessageId = Endian32(h->message_id);
  p->MessageSize = Endian32(h->message_length);
  p->ByteMsg = MemToBuf(udp->Data, udp->Size);
  p->PayloadList = NULL;

  return p;
}

bool Ikev2SetSKFromRawData(IKEv2_SK_PAYLOAD* sk, IKEv2_CRYPTO_PARAM* param) {
  if (sk == NULL || param == NULL) {
    return false;
  }

  BUF* raw = sk->raw_data;
  UINT encr_block_size = param->setting->encr->block_size;
  UINT integ_size = param->setting->integ->out_size;

  UINT rest_len = raw->Size - encr_block_size - integ_size;
  if (rest_len <= 0 || (rest_len % encr_block_size) > 0) {
    Dbg("SK init: wrong rest len %u, block size %u", rest_len, encr_block_size);
    return false;
  }

  sk->init_vector = NewBufFromMemory(raw->Buf, encr_block_size);
  sk->encrypted_payloads = NewBufFromMemory((UCHAR*)raw->Buf + encr_block_size, rest_len);
  sk->padding = NULL;
  sk->pad_length = 0;
  sk->integrity_checksum = NewBufFromMemory((UCHAR*)raw->Buf + encr_block_size + rest_len, integ_size);
  sk->decrypted_payloads = NULL;

  FreeBuf(sk->raw_data);
  sk->raw_data = NULL;

  return true;
}

IKEv2_PACKET *Ikev2ParsePacket(IKEv2_PACKET* p, void *data, UINT size, IKEv2_CRYPTO_PARAM* cparam) {
  if (p == NULL || data == NULL || size < p->MessageSize) {
    return NULL;
  }

  IKEv2_PACKET* ret = p;

  UCHAR* payload_data = ((UCHAR*)data) + sizeof(IKEv2_HEADER);
  UINT payload_size = p->MessageSize - sizeof(IKEv2_HEADER);

  UCHAR next_last_payload_type;
  p->PayloadList = Ikev2ParsePayloadList(payload_data, payload_size, p->NextPayload, &next_last_payload_type);

  if (p->PayloadList == NULL) {
    Dbg("Payload list is NULL after parsing packet");
    ret = NULL;
  }

    // Decrypt only if stage != SA_INIT
  else if (p->ExchangeType != IKEv2_SA_INIT) {
    UINT payload_count = LIST_NUM(p->PayloadList);
    if (payload_count == 0) {
      Dbg("No SK payload in packet");
      ret = NULL;
    }
    else {
      IKEv2_PACKET_PAYLOAD* payload = (IKEv2_PACKET_PAYLOAD*)LIST_DATA(p->PayloadList, payload_count - 1);
      if (payload->PayloadType != IKEv2_SK_PAYLOAD_T) {
        Dbg("Last payload != SK_PAYLOAD, parse failed");
        ret = NULL;
      }
      else {
        IKEv2_SK_PAYLOAD* sk = payload->data;
        if (Ikev2SetSKFromRawData(sk, cparam) == false) {
          Dbg("SK init failed");
          ret = NULL;
        }
        else {
          void* calced_checksum = Ikev2CalcInteg(cparam->setting->integ, cparam->key_data->sk_ai, data, size - cparam->setting->integ->out_size);

          if (calced_checksum == NULL ||
              !(sk->integrity_checksum->Size == cparam->setting->integ->out_size &&
                Cmp(calced_checksum, sk->integrity_checksum->Buf, sk->integrity_checksum->Size) == 0)) {
            Dbg("Wrong checksum of packet, fail");
            ret = NULL;
          }
          else {
            cparam->key_data->IV = sk->init_vector->Buf;
            BUF* buf = Ikev2Decrypt(sk->encrypted_payloads->Buf, sk->encrypted_payloads->Size, cparam);
            cparam->key_data->IV = NULL;

            if (buf == NULL) {
              Dbg("Packet decrypt failed");
              ret = NULL;
            }
            else {
              Copy(&sk->pad_length, (UCHAR*)buf->Buf + (buf->Size - 1), 1);
              UINT new_pay_size = buf->Size - sk->pad_length - 1;

              UCHAR dummy;
              sk->decrypted_payloads = Ikev2ParsePayloadList(buf->Buf, new_pay_size, next_last_payload_type, &dummy);
              if (sk->decrypted_payloads == NULL) {
                Dbg("Decrypted payloads == NULL");
                ret = NULL;
              }

              FreeBuf(buf);
            }
          }

          if (calced_checksum != NULL) {
            Free(calced_checksum);
          }
        }
      }
    }
  }

  return ret;
}

LIST* Ikev2ParsePayloadList(void *data, UINT size, UCHAR first_payload, UCHAR* next_last) {
  LIST* payloads = NewList(NULL);
  UINT total_read = 0;
  UCHAR cur_payload = first_payload;
  BUF* buf = MemToBuf(data, size);

  while (cur_payload != IKEv2_NO_NEXT_PAYLOAD_T) {
    IKEv2_PAYLOAD_HEADER header;

    UINT read = ReadBuf(buf, &header, sizeof(IKEv2_PAYLOAD_HEADER));
    if (read != sizeof(IKEv2_PAYLOAD_HEADER)) {
      Dbg("Broken Packet (Invalid Payload Header) got: %u, expected: %u", read, sizeof(IKEv2_PAYLOAD_HEADER));
      Ikev2FreePayloadList(payloads);
      break;
    }

    USHORT payload_size = Endian16(header.payload_length) - sizeof(IKEv2_PAYLOAD_HEADER);
    BUF* payload_data = ReadBufFromBuf(buf, payload_size);
    if (payload_data == NULL) {
      Dbg("Broken Packet (Invalid Payload Size)");
      Ikev2FreePayloadList(payloads);
      break;
    }

    if (Ikev2IsSupportedPayload(cur_payload) == true) {
      IKEv2_PACKET_PAYLOAD* payload = Ikev2DecodePayload(cur_payload, payload_data);
      if (payload == NULL) {
        Dbg("IKEv2: Broken Payload (Cannot be decoded)");
        Ikev2FreePayloadList(payloads);
        FreeBuf(payload_data);
        break;
      }
      else {
        Add(payloads, payload);
      }
    }
    else {
      Dbg("IKEv2: Unsupported Payload 0x%x", cur_payload);
      if (header.is_critical > 0) {
        /*
        If the critical flag is set
        and the payload type is unrecognized, the message MUST be rejected
        and the response to the IKE request containing that payload MUST
        include a Notify payload UNSUPPORTED_CRITICAL_PAYLOAD, indicating an
        unsupported critical payload was included.  In that Notify payload,
        the Notification Data contains the one-octet payload type.
        */
      }
    }

    cur_payload = (cur_payload == IKEv2_SK_PAYLOAD_T) ? IKEv2_NO_NEXT_PAYLOAD_T : header.next_payload;
    *next_last = header.next_payload;
    FreeBuf(payload_data);
  }

  FreeBuf(buf);
  return payloads;
}

IKEv2_PACKET_PAYLOAD* Ikev2DecodePayload(UCHAR payload_type, BUF *buf) {
  if (buf == NULL) {
    return NULL;
  }

  IKEv2_PACKET_PAYLOAD* payload = (IKEv2_PACKET_PAYLOAD*)ZeroMalloc(sizeof(IKEv2_PACKET_PAYLOAD));
  if (payload == NULL) {
    Dbg("Can't allocate memory for IKEv2_PACKET_PAYLOAD");
    return NULL;
  }
  payload->PayloadType = payload_type;
  payload->data = NULL;
  UINT error_type = IKEv2_NO_ERROR;

  Dbg("Decoding payload with type: 0x%x", payload_type);
  switch (payload_type) {
    case IKEv2_SA_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_SA_PAYLOAD));
      error_type = ikev2_SA_decode(buf, payload->data);
      break;
    case IKEv2_KE_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_KE_PAYLOAD));
      error_type = ikev2_KE_decode(buf, payload->data);
      break;
    case IKEv2_IDi_PAYLOAD_T:
    case IKEv2_IDr_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_ID_PAYLOAD));
      error_type = ikev2_ID_decode(buf, payload->data);
      break;
    case IKEv2_CERTIFICATE_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_CERT_PAYLOAD));
      error_type = ikev2_cert_decode(buf, payload->data);
      break;
    case IKEv2_CERTREQ_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_CERTREQ_PAYLOAD));
      error_type = ikev2_cert_req_decode(buf, payload->data);
      break;
    case IKEv2_AUTH_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_AUTH_PAYLOAD));
      error_type = ikev2_auth_decode(buf, payload->data);
      break;
    case IKEv2_NONCE_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_NONCE_PAYLOAD));
      error_type = ikev2_nonce_decode(buf, payload->data);
      break;
    case IKEv2_NOTIFY_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_NOTIFY_PAYLOAD));
      error_type = ikev2_notify_decode(buf, payload->data);
      break;
    case IKEv2_DELETE_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_DELETE_PAYLOAD));
      error_type = ikev2_delete_decode(buf, payload->data);
      break;
    case IKEv2_VENDOR_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_VENDOR_PAYLOAD));
      error_type = ikev2_vendor_decode(buf, payload->data);
      break;
    case IKEv2_TSi_PAYLOAD_T:
    case IKEv2_TSr_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_TS_PAYLOAD));
      error_type = ikev2_TS_decode(buf, payload->data);
      break;
    case IKEv2_SK_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_SK_PAYLOAD));
      error_type = ikev2_SK_decode(buf, payload->data);
      break;
    case IKEv2_CP_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_CP_PAYLOAD));
      error_type = ikev2_configuration_decode(buf, payload->data);
      break;
    case IKEv2_EAP_PAYLOAD_T:
      payload->data = ZeroMalloc(sizeof(IKEv2_EAP_PAYLOAD));
      error_type = ikev2_EAP_decode(buf, payload->data);
      break;
    default:
      Dbg("Unknown payload: %u", payload_type);
      error_type = IKEv2_EAP_PAYLOAD_T + 1;
      break;
  }

  if (error_type == IKEv2_NO_ERROR) {
    payload->BitArray = CloneBuf(buf);
  }
  else {
    Dbg("Error occured");
    if (payload != NULL && payload->data != NULL) {
      Free(payload->data);
      payload->data = NULL;
    }

    Free(payload);
    payload = NULL;
  }

  return payload;
}

void Ikev2FreePacket(IKEv2_PACKET *p) {
  if (p == NULL) {
    return;
  }

  Ikev2FreePayloadList(p->PayloadList);

  if (p->ByteMsg != NULL) {
    FreeBuf(p->ByteMsg);
  }

  Free(p);
}

void Ikev2FreePayloadList(LIST *payloads) {
  if (payloads == NULL) {
    return;
  }

  for (UINT i = 0; i < LIST_NUM(payloads); ++i) {
    IKEv2_PACKET_PAYLOAD *p = LIST_DATA(payloads, i);
    Ikev2FreePayload(p);
  }

  ReleaseList(payloads);
}

void Ikev2FreePayload(IKEv2_PACKET_PAYLOAD *p) {
  if (p == NULL) {
    return;
  }

  switch (p->PayloadType) {
    case IKEv2_SA_PAYLOAD_T:
      ikev2_free_SA_payload(p->data);
      break;

    case IKEv2_KE_PAYLOAD_T:
      ikev2_free_KE_payload(p->data);
      break;

    case IKEv2_IDi_PAYLOAD_T:
    case IKEv2_IDr_PAYLOAD_T:
      ikev2_free_ID_payload(p->data);
      break;

    case IKEv2_CERTIFICATE_PAYLOAD_T:
      ikev2_free_cert_payload(p->data);
      break;

    case IKEv2_CERTREQ_PAYLOAD_T:
      ikev2_free_cert_req_payload(p->data);
      break;

    case IKEv2_AUTH_PAYLOAD_T:
      ikev2_free_auth_payload(p->data);
      break;

    case IKEv2_NONCE_PAYLOAD_T:
      ikev2_free_nonce_payload(p->data);
      break;

    case IKEv2_NOTIFY_PAYLOAD_T:
      ikev2_free_notify_payload(p->data);
      break;

    case IKEv2_DELETE_PAYLOAD_T:
      ikev2_free_delete_payload(p->data);
      break;

    case IKEv2_VENDOR_PAYLOAD_T:
      ikev2_free_vendor_payload(p->data);
      break;

    case IKEv2_TSi_PAYLOAD_T:
    case IKEv2_TSr_PAYLOAD_T:
      ikev2_free_TS_payload(p->data);
      break;

    case IKEv2_SK_PAYLOAD_T:
      ikev2_free_SK_payload(p->data);
      break;

    case IKEv2_CP_PAYLOAD_T:
      ikev2_free_configuration_payload(p->data);
      break;

    case IKEv2_EAP_PAYLOAD_T:
      ikev2_free_EAP_payload(p->data);
      break;

    default:
      Dbg("Freeing payload of unknown type 0x%x", p->PayloadType);
      break;
  }

  if (p->BitArray != NULL) {
    FreeBuf(p->BitArray);
  }

  Free(p);
}

BUF* Ikev2Encrypt(void* data, UINT size, IKEv2_CRYPTO_PARAM *cparam) {
  if (data == NULL) {
    return NULL;
  }

  if (cparam == NULL) {
    Dbg("CPARAM == null, return unencrypted version");
    return NewBufFromMemory(data, size);
  }

  Dbg("Start encrypting");

  IKEv2_ENCR* encr = cparam->setting->encr;
  IKEv2_CRYPTO_KEY_DATA* key_data = cparam->key_data;

  void* decoded = ZeroMalloc(size);
  switch (encr->type) {
    case IKEv2_TRANSFORM_ID_ENCR_DES:
      if (key_data->des_key_e == NULL) {
        key_data->des_key_e = DesNewKeyValue(key_data->sk_er);
      }
      DesEncrypt(decoded, data, size, key_data->des_key_e, key_data->IV);
      break;
    case IKEv2_TRANSFORM_ID_ENCR_3DES:
      if (key_data->des3_key_e == NULL) {
        key_data->des3_key_e = Des3NewKey(key_data->sk_er, key_data->sk_er + DES_KEY_SIZE, key_data->sk_er + 2 * DES_KEY_SIZE);
      }
      Des3Encrypt(decoded, data, size, key_data->des3_key_e, key_data->IV);
      break;
    case IKEv2_TRANSFORM_ID_ENCR_RC5:
    case IKEv2_TRANSFORM_ID_ENCR_IDEA:
    case IKEv2_TRANSFORM_ID_ENCR_CAST:
    case IKEv2_TRANSFORM_ID_ENCR_BLOWFISH:
      Dbg("No realization of this encryption algo: %u", encr->type);
      Copy(decoded, data, size);
      break;
    case IKEv2_TRANSFORM_ID_ENCR_NULL:
      Copy(decoded, data, size);
      break;
    case IKEv2_TRANSFORM_ID_ENCR_AES_CBC:
      if (key_data->aes_key_e == NULL) {
        key_data->aes_key_e = AesNewKey(key_data->sk_er, key_data->encr_key_size);
      }
      AesEncrypt(decoded, data, size, key_data->aes_key_e, key_data->IV);
      break;
    case IKEv2_TRANSFORM_ID_ENCR_AES_CTR:
      Dbg("No realization of this encryption algo: %u", encr->type);
      Copy(decoded, data, size);
      break;
    default:
      Dbg("Unsupported encryption algo: %u", encr->type);
      return NULL;
  }

  return NewBufFromMemory(decoded, size);
}

BUF* Ikev2Decrypt(void* data, UINT size, IKEv2_CRYPTO_PARAM *cparam) {
  if (data == NULL || cparam == NULL) {
    return NULL;
  }

  IKEv2_ENCR* encr = cparam->setting->encr;
  IKEv2_CRYPTO_KEY_DATA* key_data = cparam->key_data;

  void* decoded = ZeroMalloc(size);
  Dbg("decrypt type: %u", encr->type);
  switch (encr->type) {
    case IKEv2_TRANSFORM_ID_ENCR_DES:
      if (key_data->des_key_d == NULL) {
        key_data->des_key_d = DesNewKeyValue(key_data->sk_ei);
      }
      DesDecrypt(decoded, data, size, key_data->des_key_d, key_data->IV);
      break;
    case IKEv2_TRANSFORM_ID_ENCR_3DES:
      if (key_data->des3_key_d == NULL) {
        key_data->des3_key_d = Des3NewKey(key_data->sk_ei, key_data->sk_ei + DES_KEY_SIZE, key_data->sk_ei + 2 * DES_KEY_SIZE);
      }
      Dbg("3DES decrypt");
      Des3Decrypt(decoded, data, size, key_data->des3_key_d, key_data->IV);
      break;
    case IKEv2_TRANSFORM_ID_ENCR_RC5:
    case IKEv2_TRANSFORM_ID_ENCR_IDEA:
    case IKEv2_TRANSFORM_ID_ENCR_CAST:
    case IKEv2_TRANSFORM_ID_ENCR_BLOWFISH:
      Dbg("No realization of BLOWFISH");
      Copy(decoded, data, size);
      break;
    case IKEv2_TRANSFORM_ID_ENCR_NULL:
      Copy(decoded, data, size);
      break;
    case IKEv2_TRANSFORM_ID_ENCR_AES_CBC:
      if (key_data->aes_key_d == NULL) {
        key_data->aes_key_d = AesNewKey(key_data->sk_ei, key_data->encr_key_size);
      }
      AesDecrypt(decoded, data, size, key_data->aes_key_d, key_data->IV);
      break;
    case IKEv2_TRANSFORM_ID_ENCR_AES_CTR:
      Dbg("No realization of ARS_CTR");
      Copy(decoded, data, size);
      break;
    default:
      Dbg("Unsupported encryption algo: %u", encr->type);
      return NULL;
  }

  return NewBufFromMemory(decoded, size);
}

BUF* Ikev2BuildPacket(IKEv2_PACKET *p) {
  if (p == NULL || p->PayloadList == NULL) {
    return NULL;
  }

  IKEv2_HEADER h;
  h.init_SPI = Endian64(p->SPIi);
  h.resp_SPI = Endian64(p->SPIr);
  h.exchange_type = p->ExchangeType;
  h.version = IKEv2_VERSION;
  h.next_payload = ((IKEv2_PACKET_PAYLOAD*)(LIST_DATA(p->PayloadList, 0)))->PayloadType;
  h.flags = ((p->FlagVersion == true) ? IKEv2_VERSION_FLAG : 0) |
            ((p->FlagInitiator == true) ? IKEv2_INITIATOR_FLAG : 0) |
            ((p->FlagResponse == true) ? IKEv2_RESPONSE_FLAG : 0);
  h.message_id = Endian32(p->MessageId);
  h.message_length = 0; // skip now

  if (p->ByteMsg != NULL) {
    FreeBuf(p->ByteMsg);
  }

  BUF* pay_list = Ikev2BuildPayloadList(p->PayloadList);
  UINT count = LIST_NUM(p->PayloadList);
  bool is_sk_last = ((count > 0) && (((IKEv2_PACKET_PAYLOAD*)LIST_DATA(p->PayloadList, count - 1))->PayloadType == IKEv2_SK_PAYLOAD_T)) ? true : false;
  BUF* ret = NewBuf();
  p->MessageSize = sizeof(h) + pay_list->Size;
  if (is_sk_last == true) {
    IKEv2_PACKET_PAYLOAD* packetPayload = ((IKEv2_PACKET_PAYLOAD*)LIST_DATA(p->PayloadList, count - 1));
    Dbg("Adding %u bytes to message size due to SK", ((IKEv2_SK_PAYLOAD*)packetPayload->data)->integ_len);
    p->MessageSize += ((IKEv2_SK_PAYLOAD*)packetPayload->data)->integ_len;
  }
  h.message_length = Endian32(p->MessageSize);
  WriteBuf(ret, &h, sizeof(h));
  WriteBufBuf(ret, pay_list);
  FreeBuf(pay_list);

  p->ByteMsg = (is_sk_last == true) ? NULL : CloneBuf(ret); // calc after if sk last
  return ret;
}

BUF* Ikev2BuildPayloadList(LIST *pay_list) {
  assert(pay_list != NULL);

  BUF* ret = NewBuf();

  UINT len = LIST_NUM(pay_list);
  for (UINT i = 0; i < len; ++i) {
    IKEv2_PACKET_PAYLOAD* payload = (IKEv2_PACKET_PAYLOAD*)LIST_DATA(pay_list, i);
    BUF* pay_buf = Ikev2BuildPayload(payload);

    if (pay_buf != NULL) {
      IKEv2_PAYLOAD_HEADER header;
      header.is_critical = 0;
      if (i < len - 1) {
        header.next_payload = ((IKEv2_PACKET_PAYLOAD*)(LIST_DATA(pay_list, i + 1)))->PayloadType;
      }
      else {
        if (payload->PayloadType == IKEv2_SK_PAYLOAD_T) {
          IKEv2_SK_PAYLOAD* sk = payload->data;
          LIST* decrypted = sk->decrypted_payloads;
          if (LIST_NUM(decrypted) == 0) {
            Dbg("Setting SK next_payload to next payload value");
            header.next_payload = sk->next_payload;
          }
          else {
            Dbg("Setting SK next_payload to not 0");
            header.next_payload = ((IKEv2_PACKET_PAYLOAD*)(LIST_DATA(decrypted, 0)))->PayloadType;
          }
        }
        else {
          header.next_payload = IKEv2_NO_NEXT_PAYLOAD_T;
        }
      }

      UCHAR add = 0;
      if (payload->PayloadType == IKEv2_SK_PAYLOAD_T) {
        Dbg("Adding integ checksum padding %u bytes to payload generic header", ((IKEv2_SK_PAYLOAD*)payload->data)->integ_len);
        add = ((IKEv2_SK_PAYLOAD*)payload->data)->integ_len;
      }
      header.payload_length = Endian16(sizeof(header) + pay_buf->Size + add);

      WriteBuf(ret, &header, sizeof(header));
      WriteBufBuf(ret, pay_buf);

      FreeBuf(pay_buf);
    }
    else {
      Dbg("Encoded buffer is NULL");
    }
  }

  return ret;
}

BUF* Ikev2BuildPayload(IKEv2_PACKET_PAYLOAD *p) {
  if (p == NULL) {
    return NULL;
  }

  BUF* ret = NULL;
  switch (p->PayloadType) {
    case IKEv2_SA_PAYLOAD_T:
      ret = ikev2_SA_encode(p->data);
      break;

    case IKEv2_KE_PAYLOAD_T:
      ret = ikev2_KE_encode(p->data);
      break;

    case IKEv2_IDi_PAYLOAD_T:
    case IKEv2_IDr_PAYLOAD_T:
      ret = ikev2_ID_encode(p->data);
      break;

    case IKEv2_CERTIFICATE_PAYLOAD_T:
      ret = ikev2_cert_encode(p->data);
      break;

    case IKEv2_CERTREQ_PAYLOAD_T:
      ret = ikev2_cert_req_encode(p->data);
      break;

    case IKEv2_AUTH_PAYLOAD_T:
      ret = ikev2_auth_encode(p->data);
      break;

    case IKEv2_NONCE_PAYLOAD_T:
      ret = ikev2_nonce_encode(p->data);
      break;

    case IKEv2_NOTIFY_PAYLOAD_T:
      ret = ikev2_notify_encode(p->data);
      break;

    case IKEv2_DELETE_PAYLOAD_T:
      ret = ikev2_delete_encode(p->data);
      break;

    case IKEv2_VENDOR_PAYLOAD_T:
      ret = ikev2_vendor_encode(p->data);
      break;

    case IKEv2_TSi_PAYLOAD_T:
    case IKEv2_TSr_PAYLOAD_T:
      ret = ikev2_TS_encode(p->data);
      break;

    case IKEv2_SK_PAYLOAD_T:
      ret = ikev2_SK_encode(p->data);
      break;

    case IKEv2_CP_PAYLOAD_T:
      ret = ikev2_configuration_encode(p->data);
      break;

    case IKEv2_EAP_PAYLOAD_T:
      ret = ikev2_EAP_encode(p->data);
      break;

    default:
      Debug("Building payload of unknown type %d\n", p->PayloadType);
      break;
  }

  return ret;
}

LIST* Ikev2GetAllPayloadsByType(LIST* payloads, UCHAR type) {
  LIST* ret = NewListFast(NULL);

  if (payloads == NULL) {
    return ret;
  }

  UINT size = LIST_NUM(payloads);
  for (UINT i = 0; i < size; ++i) {
    IKEv2_PACKET_PAYLOAD* payload = (IKEv2_PACKET_PAYLOAD*)LIST_DATA(payloads, i);
    if (payload->PayloadType == type) {
      Add(ret, payload);
    }
  }

  return ret;
}

IKEv2_PACKET_PAYLOAD* Ikev2GetPayloadByType(LIST* payloads, UCHAR type, UINT index) {
  if (payloads == NULL) {
    return NULL;
  }

  LIST* type_list = Ikev2GetAllPayloadsByType(payloads, type);
  IKEv2_PACKET_PAYLOAD* ret = NULL;

  if (LIST_NUM(type_list) <= index) {
    Dbg("No such index: ask %u, len %u", index, LIST_NUM(type_list));
  }
  else {
    ret = (IKEv2_PACKET_PAYLOAD*)LIST_DATA(type_list, index);
  }

  ReleaseList(type_list);
  return ret;
}

bool Ikev2IsValidTransformType(const IKEv2_SA_TRANSFORM* transform) {
  if (transform == NULL) {
    return false;
  }

  return (transform->transform.type >= IKEv2_TRANSFORM_TYPE_ENCR && transform->transform.type <= IKEv2_TRANSFORM_TYPE_ESN);
}

bool Ikev2IsValidTransform(IKEv2_CRYPTO_ENGINE* engine, IKEv2_SA_TRANSFORM* transform) {
  if (transform == NULL) {
    return false;
  }

  bool ok = false;
  // check id
  switch (transform->transform.type) {
    case IKEv2_TRANSFORM_TYPE_ENCR:
      ok = ((transform->transform.ID >= IKEv2_TRANSFORM_ID_ENCR_DES && transform->transform.ID <= IKEv2_TRANSFORM_ID_ENCR_BLOWFISH) ||
            (transform->transform.ID >= IKEv2_TRANSFORM_ID_ENCR_NULL && transform->transform.ID <= IKEv2_TRANSFORM_ID_ENCR_AES_CTR))
           ? true : false;
      break;
    case IKEv2_TRANSFORM_TYPE_PRF:
      ok = (transform->transform.ID >= IKEv2_TRANSFORM_ID_PRF_HMAC_MD5 && transform->transform.ID <= IKEv2_TRANSFORM_ID_PRF_HMAC_SHA1) ? true : false;
      break;
    case IKEv2_TRANSFORM_TYPE_INTEG:
      /*ok = ((transform->transform.ID >= IKEv2_TRANSFORM_ID_AUTH_NONE && transform->transform.ID <= IKEv2_TRANSFORM_ID_AUTH_HMAC_SHA1_96) ||
          (transform->transform.ID == IKEv2_TRANSFORM_ID_AUTH_AES_XCBC_96)) ? true : false;*/
      ok = (transform->transform.ID >= IKEv2_TRANSFORM_ID_AUTH_NONE && transform->transform.ID <= IKEv2_TRANSFORM_ID_AUTH_HMAC_SHA1_96) ? true : false;
      break;
    case IKEv2_TRANSFORM_TYPE_DH:
      ok = ((transform->transform.ID >= IKEv2_TRANSFORM_ID_DH_NONE && transform->transform.ID <= IKEv2_TRANSFORM_ID_DH_1024) ||
            (transform->transform.ID == IKEv2_TRANSFORM_ID_DH_1536) ||
            (transform->transform.ID >= IKEv2_TRANSFORM_ID_DH_2048 && transform->transform.ID <= IKEv2_TRANSFORM_ID_DH_8192)) ? true : false;
      break;
    case IKEv2_TRANSFORM_TYPE_ESN:
      ok = (transform->transform.ID >= IKEv2_TRANSFORM_ID_NO_ESN && transform->transform.ID <= IKEv2_TRANSFORM_ID_ESN) ? true : false;
      break;
    default:
      break;
  }

  if (ok == true) {
    UINT attrCount = LIST_NUM(transform->attributes);
    for (UINT i = 0; i < attrCount; ++i) {
      IKEv2_TRANSFORM_ATTRIBUTE* attr = (IKEv2_TRANSFORM_ATTRIBUTE*)LIST_DATA(transform->attributes, i);
      if (attr->type != IKEv2_ATTRIBUTE_TYPE_KEY_LENGTH) {
        ok = false;
        break;
      }
    }
  }

  // check key size of encryption transform
  if (ok == true && transform->transform.type == IKEv2_TRANSFORM_TYPE_ENCR) {
    IKEv2_ENCR* encr = Ikev2GetEncr(engine, transform->transform.ID);
    UINT attrCount = LIST_NUM(transform->attributes);
    if (encr->is_fixed == true) {
      if (encr->key_info.fixed.key_count == 1 && attrCount > 0) {
        ok = false;
      }
      else if (encr->key_info.fixed.key_count > 1) {
        if (attrCount != 1) {
          ok = false;
        }
        else {
          USHORT val = ((IKEv2_TRANSFORM_ATTRIBUTE*)(LIST_DATA(transform->attributes, 0)))->value / 8;
          bool found = false;
          for (UINT i = 0; i < encr->key_info.fixed.key_count; ++i) {
            if (encr->key_info.fixed.key_sizes[i] == val) {
              found = true;
              break;
            }
          }

          ok = found;
        }
      }
    }
    else {
      if (attrCount > 0) {
        if (attrCount != 1) {
          ok = false;
        }
        else {
          USHORT val = ((IKEv2_TRANSFORM_ATTRIBUTE*)(LIST_DATA(transform->attributes, 0)))->value / 8;
          if (!(encr->key_info.range.min_key_len <= val && encr->key_info.range.max_key_len >= val)) {
            ok = false;
          }
        }
      }
    }
  }

  return ok;
}

LIST* Ikev2GetTransformsByType(IKEv2_CRYPTO_ENGINE* engine, IKEv2_SA_PROPOSAL* proposal, UCHAR type) {
  if (proposal == NULL) {
    return NULL;
  }

  LIST* ret = NULL;
  for (UCHAR i = 0; i < proposal->transform_number; ++i) {
    IKEv2_SA_TRANSFORM* transform = (IKEv2_SA_TRANSFORM*)LIST_DATA(proposal->transforms, i);
    if ((transform->transform.type == type) && (Ikev2IsValidTransform(engine, transform))) {
      if (ret == NULL) {
        ret = NewList(NULL);
      }

      Add(ret, transform);
    }
  }

  return ret;
}

void Ikev2SetKeyLength(IKEv2_ENCR* encr, IKEv2_CRYPTO_SETTING* setting, IKEv2_SA_TRANSFORM* transform) {
  if (encr == NULL || setting == NULL || transform == NULL) {
    return;
  }

  UINT attrCount = LIST_NUM(transform->attributes);
  if (encr->is_fixed == true) {
    if (encr->key_info.fixed.key_count == 1) {
      setting->key_size = encr->key_info.fixed.key_sizes[0];
    }
    else {
      USHORT val = ((IKEv2_TRANSFORM_ATTRIBUTE*)(LIST_DATA(transform->attributes, 0)))->value / 8;
      setting->key_size = val;
    }
  }
  else {
    if (attrCount > 0) {
      USHORT val = ((IKEv2_TRANSFORM_ATTRIBUTE*)(LIST_DATA(transform->attributes, 0)))->value / 8;
      setting->key_size = val;
    }
    else {
      setting->key_size = encr->key_info.range.default_key;
    }
  }
}

bool Ikev2IsTransformPresent(IKEv2_SA_PROPOSAL* proposal, UCHAR type) {
  if (proposal == NULL) {
    return false;
  }

  for (UCHAR i = 0; i < proposal->transform_number; ++i) {
    IKEv2_SA_TRANSFORM* transform = (IKEv2_SA_TRANSFORM*)LIST_DATA(proposal->transforms, i);
    if (transform->transform.type == type) {
      return true;
    }
  }

  return false;
}

// Some memory leaks here
IKEv2_PACKET_PAYLOAD* Ikev2ChooseBestIKESA(IKEv2_SERVER* ike, IKEv2_SA_PAYLOAD* sa, IKEv2_CRYPTO_SETTING* setting, UCHAR protocol) {
  if (sa == NULL) {
    return NULL;
  }

  IKEv2_PACKET_PAYLOAD* ret = Ikev2CreatePacketPayload(IKEv2_SA_PAYLOAD_T, sizeof(IKEv2_SA_PAYLOAD));
  if (ret == NULL) {
    Dbg("Failed to allocate mem for IKEv2_PACKET_PAYLOAD");
    return NULL;
  }

  IKEv2_SA_PAYLOAD* ret_sa = ret->data;
  //ret_sa->proposals = NewList(NULL);
  LIST** ret_props = &(ret_sa->proposals);

  UINT prop_count = LIST_NUM(sa->proposals);
  Dbg("Iterating proposals: %u", prop_count);
  for (UINT i = 0; i < prop_count; ++i) {
    IKEv2_SA_PROPOSAL* proposal = (IKEv2_SA_PROPOSAL*)LIST_DATA(sa->proposals, i);
    Debug("Proposal %u, %u transforms:\n", i, proposal->transform_number);
    for (UCHAR j = 0; j < proposal->transform_number; ++j) {
      IKEv2_SA_TRANSFORM* transform = (IKEv2_SA_TRANSFORM*)LIST_DATA(proposal->transforms, j);
      Debug("\tTransform %u, type= %u, id = %u, attributes count = %u\n", j, transform->transform.type, transform->transform.ID, LIST_NUM(transform->attributes));
    }
  }

  bool ok = false;
  for (UINT i = 0; i < prop_count; ++i) {
    IKEv2_SA_PROPOSAL* proposal = (IKEv2_SA_PROPOSAL*)LIST_DATA(sa->proposals, i);

    if (proposal->protocol_id == protocol) {
      bool ok_prop = true;
      for (UCHAR j = 0; j < proposal->transform_number; ++j) {
        IKEv2_SA_TRANSFORM* transform = (IKEv2_SA_TRANSFORM*)LIST_DATA(proposal->transforms, j);
        if (Ikev2IsValidTransformType(transform) == false) {
          Dbg("Proposal check failed, transform is not valid, proposal rejected");
          ok_prop = false;
          break;
        }
      }

      if (ok_prop == false){
        continue;
      }

      bool isEncrPresent = Ikev2IsTransformPresent(proposal, IKEv2_TRANSFORM_TYPE_ENCR);
      bool isPrfPresent = Ikev2IsTransformPresent(proposal, IKEv2_TRANSFORM_TYPE_PRF);
      bool isIntegPresent = Ikev2IsTransformPresent(proposal, IKEv2_TRANSFORM_TYPE_INTEG);
      bool isDhPresent = Ikev2IsTransformPresent(proposal, IKEv2_TRANSFORM_TYPE_DH);
      bool isEsnPresent = Ikev2IsTransformPresent(proposal, IKEv2_TRANSFORM_TYPE_ESN);

      LIST* encr = Ikev2GetTransformsByType(ike->engine, proposal, IKEv2_TRANSFORM_TYPE_ENCR);
      LIST* prf = Ikev2GetTransformsByType(ike->engine, proposal, IKEv2_TRANSFORM_TYPE_PRF);
      LIST* integ = Ikev2GetTransformsByType(ike->engine, proposal, IKEv2_TRANSFORM_TYPE_INTEG);
      LIST* dh = Ikev2GetTransformsByType(ike->engine, proposal, IKEv2_TRANSFORM_TYPE_DH);
      LIST* esn = Ikev2GetTransformsByType(ike->engine, proposal, IKEv2_TRANSFORM_TYPE_ESN);

      //MANDATORY: ENCR, PRF, INTEG, D-H
      bool mandatory = false;
      switch (protocol) {
        case IKEv2_PROPOSAL_PROTOCOL_IKE:
          mandatory = (LIST_NUM(encr) > 0) && (LIST_NUM(prf) > 0) && (LIST_NUM(integ) > 0) && (LIST_NUM(dh) > 0);
          break;
        case IKEv2_PROPOSAL_PROTOCOL_AH:
          Dbg("Try to get SA for AH, skipping...\n");
          break;
        case IKEv2_PROPOSAL_PROTOCOL_ESP: {
          mandatory = (LIST_NUM(encr) > 0) && (LIST_NUM(esn) > 0);
          if (mandatory == true) {
            mandatory = (!isIntegPresent || (LIST_NUM(integ) > 0)) && (!isDhPresent || (LIST_NUM(dh) > 0));
          }
          break;
        }
        default:
          Dbg("Not yet supported proposal protocol: %u\n", protocol);
          break;
      }

      if (mandatory) {
        IKEv2_SA_PROPOSAL* cur_prop = ZeroMalloc(sizeof(IKEv2_SA_PROPOSAL));
        if (cur_prop == NULL) {
          Dbg("Failed to allocate mem IKEv2_SA_PROPOSAL on iter %u", i);
          Ikev2FreePayload(ret);

          ReleaseList(encr);
          ReleaseList(prf);
          ReleaseList(integ);
          ReleaseList(dh);
          ReleaseList(esn);

          return NULL;
        }

        *ret_props = NewList(NULL);
        Add(*ret_props, cur_prop);

        cur_prop->is_last = proposal->is_last;
        cur_prop->length = 0;
        cur_prop->number = proposal->number;
        cur_prop->protocol_id = protocol;
        cur_prop->SPI = (proposal->SPI == NULL) ? NULL : CloneBuf(proposal->SPI);
        cur_prop->SPI_size = proposal->SPI_size;

        switch (protocol) {
          case IKEv2_PROPOSAL_PROTOCOL_IKE:
            cur_prop->transform_number = 4;
            break;
          case IKEv2_PROPOSAL_PROTOCOL_AH:
            cur_prop->transform_number = 0;
            break;
          case IKEv2_PROPOSAL_PROTOCOL_ESP:
            cur_prop->transform_number = 2;
            break;
          default:
            cur_prop->transform_number = 0;
            continue;
        }
        cur_prop->transforms = NewList(NULL);

        switch (protocol) {
          case IKEv2_PROPOSAL_PROTOCOL_IKE: {
            IKEv2_SA_TRANSFORM* encr_transform = (IKEv2_SA_TRANSFORM*)LIST_DATA(encr, Rand32() % LIST_NUM(encr));
            IKEv2_SA_TRANSFORM* prf_transform = (IKEv2_SA_TRANSFORM*)LIST_DATA(prf, Rand32() % LIST_NUM(prf));
            IKEv2_SA_TRANSFORM* integ_transform = (IKEv2_SA_TRANSFORM*)LIST_DATA(integ, Rand32() % LIST_NUM(integ));

            UINT dh_count = LIST_NUM(dh);
            IKEv2_SA_TRANSFORM* dh_transform = (IKEv2_SA_TRANSFORM*)LIST_DATA(dh, 0);
            for (UINT j = 1; j < dh_count; ++j) {
              IKEv2_SA_TRANSFORM* curDH = (IKEv2_SA_TRANSFORM*)LIST_DATA(dh, j);
              if (curDH->transform.ID > dh_transform->transform.ID) {
                dh_transform = curDH;
              }
            }

            setting->encr = Ikev2GetEncr(ike->engine, encr_transform->transform.ID);
            if (setting->encr == NULL) {
              Dbg("Got ENCR == NULL in SA choice, ERROR\n");
            }
            else {
              Ikev2SetKeyLength(setting->encr, setting, encr_transform);
            }
            setting->prf = Ikev2GetPRF(ike->engine, prf_transform->transform.ID);
            if (setting->prf == NULL) {
              Dbg("Got PRF == NULL in SA choice, ERROR\n");
            }
            setting->integ = Ikev2GetInteg(ike->engine, integ_transform->transform.ID);
            if (setting->integ == NULL) {
              Dbg("Got INTEG == NULL in SA choice, ERROR\n");
            }

            setting->dh = Ikev2GetDH(ike->engine, dh_transform->transform.ID);
            if (setting->dh == NULL) {
              Dbg("Got DH == NULL in SA choice, ERROR\n");
            }

            Add(cur_prop->transforms, Ikev2CloneTransform(encr_transform));
            Add(cur_prop->transforms, Ikev2CloneTransform(prf_transform));
            Add(cur_prop->transforms, Ikev2CloneTransform(integ_transform));
            Add(cur_prop->transforms, Ikev2CloneTransform(dh_transform));

            ok = true;
            break;
          }
          case IKEv2_PROPOSAL_PROTOCOL_AH:
            Dbg("Got AH, wtf");
            break;
          case IKEv2_PROPOSAL_PROTOCOL_ESP: {
            IKEv2_SA_TRANSFORM* encr_transform = (IKEv2_SA_TRANSFORM*)LIST_DATA(encr, Rand32() % LIST_NUM(encr));
            IKEv2_SA_TRANSFORM* integ_transform = (LIST_NUM(integ) > 0) ? (IKEv2_SA_TRANSFORM*)LIST_DATA(integ, Rand32() % LIST_NUM(integ)) : NULL;
            IKEv2_SA_TRANSFORM* dh_transform = (LIST_NUM(dh) > 0) ? (IKEv2_SA_TRANSFORM*)LIST_DATA(dh, Rand32() % LIST_NUM(dh)) : NULL;
            IKEv2_SA_TRANSFORM* esn_transform = (IKEv2_SA_TRANSFORM*)LIST_DATA(esn, Rand32() % LIST_NUM(esn));

            UCHAR transform_count = 0;
            setting->encr = Ikev2GetEncr(ike->engine, encr_transform->transform.ID);
            if (setting->encr == NULL) {
              Dbg("Got ENCR == NULL in SA choice, ERROR");
            }
            else {
              Ikev2SetKeyLength(setting->encr, setting, encr_transform);
              transform_count++;
            }

            if (integ_transform != NULL) {
              setting->integ = Ikev2GetInteg(ike->engine, integ_transform->transform.ID);
              transform_count++;
              if (setting->integ == NULL) {
                Dbg("Got INTEG == NULL in SA choice, ERROR");
              }
            }

            if (dh_transform != NULL) {
              setting->dh = Ikev2GetDH(ike->engine, dh_transform->transform.ID);
              transform_count++;
              if (setting->dh == NULL) {
                Dbg("Got DH == NULL in SA choice, ERROR");
              }
            }

            setting->extended_esn = esn_transform->transform.ID == IKEv2_TRANSFORM_ID_ESN;
            transform_count++;

            Add(cur_prop->transforms, Ikev2CloneTransform(encr_transform));

            if (integ != NULL) {
              Add(cur_prop->transforms, Ikev2CloneTransform(integ_transform));
            }

            if (dh_transform != NULL) {
              Add(cur_prop->transforms, Ikev2CloneTransform(dh_transform));
            }

            Add(cur_prop->transforms, Ikev2CloneTransform(esn_transform));
            cur_prop->transform_number = transform_count;

            ok = true;
            break;
          }
          default:
            continue;
        }
      }

      ReleaseList(encr);
      ReleaseList(prf);
      ReleaseList(integ);
      ReleaseList(dh);
      ReleaseList(esn);

      if (ok == true) {
        break;
      }
    }
  }

  if (ok == false) {
    Dbg("SA not chosen");
    Ikev2FreePayload(ret);
    return NULL;
  }

  IKEv2_SA_PAYLOAD* sap = ret->data;
  prop_count = LIST_NUM(sap->proposals);
  Dbg("Iterating proposals from chosen SA: %u", prop_count);
  for (UINT i = 0; i < prop_count; ++i) {
    IKEv2_SA_PROPOSAL* proposal = (IKEv2_SA_PROPOSAL*)LIST_DATA(sap->proposals, i);
    Debug("Proposal %u, %u transforms:\n", i, proposal->transform_number);
    for (UCHAR j = 0; j < proposal->transform_number; ++j) {
      IKEv2_SA_TRANSFORM* transform = (IKEv2_SA_TRANSFORM*)LIST_DATA(proposal->transforms, j);
      Debug("\tTransform %u, type= %u, id = %u, attributes count = %u\n", j, transform->transform.type, transform->transform.ID, LIST_NUM(transform->attributes));
    }
  }

  Dbg("Choose finished");
  return ret;
}

IKEv2_CLIENT* Ikev2GetClient(IKEv2_SERVER* server, IP* clientIP, UINT clientPort, IP* serverIP, UINT serverPort) {
  if (server == NULL || clientIP == NULL || serverIP == NULL) {
    return NULL;
  }

  LIST* SAs = server->SAs;
  UINT saCount = LIST_NUM(SAs);
  for (UINT i = 0; i < saCount; ++i) {
    IKEv2_SA* sa = LIST_DATA(SAs, i);
    IKEv2_CLIENT* c = sa->client;

    if (CmpIpAddr(&c->client_ip, clientIP) == 0 && CmpIpAddr(&c->server_ip, serverIP) &&
        c->client_port == clientPort && c->server_port == serverPort) {
      return c;
    }
  }

  return NULL;
}

IKEv2_SA* Ikev2GetSABySPIAndClient(IKEv2_SERVER* server, UINT64 SPIi, UINT64 SPIr, IKEv2_CLIENT* client) {
  if (server == NULL) {
    return NULL;
  }

  LIST* SAs = server->SAs;
  UINT saCount = LIST_NUM(SAs);
  for (UINT i = 0; i < saCount; ++i) {
    IKEv2_SA* sa = LIST_DATA(SAs, i);
    Dbg("got SA: spi_i: %u spi_r: %u", sa->SPIi, sa->SPIr);
    //IKEv2_CLIENT* c = sa->client;

    if (sa->SPIi == SPIi && sa->SPIr == SPIr) {
      return sa;
    }
  }

  return NULL;
}

IKEv2_IPSECSA* Ikev2GetIPSECSA(IKEv2_SERVER* server, IKEv2_SA* ike_sa, UINT SPI) {
  if (server == NULL || ike_sa == NULL) {
    Dbg("Server == NULL || ike_sa == NULL in Get IPSEC_SA");
    return NULL;
  }

  UINT ipsec_sa_count = LIST_NUM(server->ipsec_SAs);
  for (UINT i = 0; i < ipsec_sa_count; ++i) {
    IKEv2_IPSECSA* sa = (IKEv2_IPSECSA*)LIST_DATA(server->ipsec_SAs, i);
    if (sa->SPI == SPI) {
      IKEv2_SA* temp_sa = sa->ike_sa;
      if (temp_sa->SPIi == ike_sa->SPIi && temp_sa->SPIr == ike_sa->SPIr) {
        return sa;
      }
    }
  }

  return NULL;
}

BUF* Ikev2GenerateNonce(UCHAR key_size) {
  BUF* ret = NewBuf();
  UCHAR size = max(IKEv2_MIN_NONCE_SIZE, min(IKEv2_MAX_NONCE_SIZE, key_size / 2));
  Dbg("nonce size is %d", size);

  for (UCHAR i = 0; i < size; ++i) {
    WriteBufChar(ret, Rand8());
  }

  return ret;
}

IKEv2_PACKET* Ikev2CreatePacket(UINT64 SPIi, UINT64 SPIr, UCHAR exchange_type,
                                bool is_response, bool version, bool is_initiator,
                                UINT msgID, LIST* payloads) {
  assert(payloads != NULL && LIST_NUM(payloads) > 0);

  IKEv2_PACKET* packet = (IKEv2_PACKET*)ZeroMalloc(sizeof(IKEv2_PACKET));
  if (packet == NULL) {
    Dbg("failed to malloc");
    return NULL;
  }

  packet->SPIi = SPIi;
  packet->SPIr = SPIr;
  packet->ExchangeType = exchange_type;
  packet->FlagResponse = is_response;
  packet->FlagVersion = version;
  packet->FlagInitiator = is_initiator;
  packet->MessageId = msgID;
  packet->ByteMsg = NULL;
  packet->PayloadList = payloads;
  packet->MessageSize = 0; // it will be calculated afterwards

  return packet;
}

IKEv2_PACKET_PAYLOAD* Ikev2CreatePacketPayload(UCHAR type, UINT sizeofData) {
  IKEv2_PACKET_PAYLOAD* payload = (IKEv2_PACKET_PAYLOAD*)ZeroMalloc(sizeof(IKEv2_PACKET_PAYLOAD));
  if (payload == NULL) {
    return NULL;
  }

  payload->PayloadType = type;
  payload->BitArray = NULL;
  payload->data = ZeroMalloc(sizeofData);
  if (payload->data == NULL) {
    Free(payload);
    return NULL;
  }

  return payload;
}

IKEv2_PACKET_PAYLOAD* Ikev2CreateKE(USHORT dh, BUF* buf) {
  IKEv2_PACKET_PAYLOAD* payload = Ikev2CreatePacketPayload(IKEv2_KE_PAYLOAD_T, sizeof(IKEv2_KE_PAYLOAD));
  if (payload == NULL) {
    Debug("%s:%d error: failed to allocate mem %d\n", __func__, __LINE__,
          sizeof(IKEv2_PACKET_PAYLOAD));
    return NULL;
  }

  IKEv2_KE_PAYLOAD* KE = (IKEv2_KE_PAYLOAD*)payload->data;
  KE->DH_transform_ID = dh;
  KE->key_data = CloneBuf(buf);

  return payload;
}

IKEv2_PACKET_PAYLOAD* Ikev2CreateAuth(USHORT method, BUF* data) {
  IKEv2_PACKET_PAYLOAD* payload = Ikev2CreatePacketPayload(IKEv2_AUTH_PAYLOAD_T, sizeof(IKEv2_AUTH_PAYLOAD));
  if (payload == NULL) {
    Debug("%s:%d error: failed to allocate mem %d\n", __func__, __LINE__,
          sizeof(IKEv2_PACKET_PAYLOAD));
    return NULL;
  }

  IKEv2_AUTH_PAYLOAD* auth = (IKEv2_AUTH_PAYLOAD*)payload->data;
  auth->auth_method = method;
  auth->data = CloneBuf(data);

  return payload;
}

IKEv2_PACKET_PAYLOAD* Ikev2CreateNonce(BUF* buf) {
  IKEv2_PACKET_PAYLOAD* payload = Ikev2CreatePacketPayload(IKEv2_NONCE_PAYLOAD_T, sizeof(IKEv2_NONCE_PAYLOAD));
  if (payload == NULL) {
    Debug("%s:%d error: failed to allocate mem %d\n", __func__, __LINE__,
          sizeof(IKEv2_PACKET_PAYLOAD));
    return NULL;
  }

  IKEv2_NONCE_PAYLOAD* nonce = (IKEv2_NONCE_PAYLOAD*)payload->data;
  nonce->nonce = CloneBuf(buf);

  return payload;
}

void* Ikev2CreateIV(UINT size) {
  UCHAR* ret = ZeroMalloc(size);

  for (UINT i = 0; i < size; ++i) {
    ret[i] = Rand8();
  }

  return ret;
}

IKEv2_PACKET_PAYLOAD* Ikev2CreateSK(LIST* payloads, IKEv2_CRYPTO_PARAM* cparam) {
  if (payloads == NULL || cparam == NULL) {
    return NULL;
  }

  IKEv2_PACKET_PAYLOAD* ret = Ikev2CreatePacketPayload(IKEv2_SK_PAYLOAD_T, sizeof(IKEv2_SK_PAYLOAD));
  if (ret == NULL) {
    return NULL;
  }

  IKEv2_SK_PAYLOAD* sk = (IKEv2_SK_PAYLOAD*)ret->data;

  UINT block_size = cparam->setting->encr->block_size;
  void* IV = Ikev2CreateIV(block_size);
  sk->init_vector = NewBufFromMemory(IV, block_size);

  BUF* pay_buf = Ikev2BuildPayloadList(payloads);
  UINT pay_size = pay_buf->Size + 1;
  UINT rest_pad = pay_size % block_size;
  UCHAR pad_length = (rest_pad == 0) ? 0 : block_size - rest_pad;
  Dbg("Pad_length = %u", pad_length);
  UINT new_length = pay_size + pad_length;

  void* src = ZeroMalloc(new_length);
  Copy(src, pay_buf->Buf, pay_buf->Size);
  // Make padding = 0x00000... value
  Copy((UCHAR*)src + new_length - 1, &pad_length, 1);
  //DbgPointer("Before encrypt: ", src, new_length);
  cparam->key_data->IV = IV;
  BUF* encrypted = Ikev2Encrypt(src, new_length, cparam);
  Free(IV);
  if (encrypted == NULL) {
    Debug("Encrypting failed...\n");
    FreeBuf(pay_buf);
    Free(src);

    return NULL;
  }
  //DbgBuf("After encrypt:", encrypted);

  sk->encrypted_payloads = encrypted;
  sk->padding = NULL;
  sk->pad_length = pad_length; // for debug purposes
  sk->integrity_checksum = NULL; // will be calculated afterwards
  sk->decrypted_payloads = NULL;
  sk->next_payload = LIST_NUM(payloads) == 0 ? IKEv2_NO_NEXT_PAYLOAD_T : ((IKEv2_PACKET_PAYLOAD*)(LIST_DATA(payloads, 0)))->PayloadType;
  sk->integ_len = cparam->setting->integ->out_size;

  FreeBuf(pay_buf);
  Free(src);

  return ret;
}

IKEv2_PACKET_PAYLOAD* Ikev2CreateID(UCHAR type, BUF* buf, bool is_responder) {
  UCHAR ptype = IKEv2_IDi_PAYLOAD_T;
  if (is_responder) {
    ptype = IKEv2_IDr_PAYLOAD_T;
  }

  IKEv2_PACKET_PAYLOAD* payload = Ikev2CreatePacketPayload(ptype, sizeof(IKEv2_ID_PAYLOAD));
  if (payload == NULL) {
    Debug("%s:%d error: failed to allocate mem %d\n", __func__, __LINE__,
          sizeof(IKEv2_PACKET_PAYLOAD));
    return NULL;
  }

  IKEv2_ID_PAYLOAD* id = (IKEv2_ID_PAYLOAD*)payload->data;

  switch (type) {
    case IKEv2_DH_ID_IPV4_ADDR:
    case IKEv2_DH_ID_FQDN:
    case IKEv2_DH_ID_RFC822_ADDR:
    case IKEv2_DH_ID_IPV6_ADDR:
    case IKEv2_DH_ID_DER_ASN1_DN:
    case IKEv2_DH_ID_DER_ASN1_GN:
    case IKEv2_DH_ID_KEY_ID:
      id->ID_type = type;
      id->data = CloneBuf(buf);
      break;
    default:
      Ikev2FreePayload(payload);
      Dbg("Trying to set unsupported ID response type %u\n", type);
      return NULL;
  }

  return payload;
}

IKEv2_PACKET_PAYLOAD* Ikev2CreateNotify (USHORT type, BUF* spi, BUF* message, bool contains_child_sa) {
  IKEv2_PACKET_PAYLOAD* payload = Ikev2CreatePacketPayload(IKEv2_NOTIFY_PAYLOAD_T, sizeof(IKEv2_NOTIFY_PAYLOAD));
  if (payload == NULL) {
    Dbg("error: can't create payload");
    return NULL;
  }
  payload->BitArray = NULL;

  if (contains_child_sa) {
    // TODO rfc page 100
  }

  IKEv2_NOTIFY_PAYLOAD* notify = (IKEv2_NOTIFY_PAYLOAD*)payload->data;

  switch (type) {
    case IKEv2_INVALID_SELECTORS:
    case IKEv2_REKEY_SA:
    case IKEv2_CHILD_SA_NOT_FOUND:
      if (spi == NULL || spi->Size == 0) {
        Ikev2FreePayload(payload);
        Dbg("with such type as %d SPI MUST be provided, got NULL", type);
        return NULL;
      }
      notify->protocol_id = 0;
      notify->spi_size = (UCHAR)spi->Size;
      notify->spi = CloneBuf(spi);
      break;
    default:
      notify->protocol_id = 0;
      notify->spi_size = 0;
      notify->spi = NULL;
  }

  notify->notification_type = type;
  notify->message = CloneBuf(message);

  return payload;
}

IKEv2_PACKET_PAYLOAD* Ikev2CreateCP(IKEv2_CP_PAYLOAD *peer_conf, LIST* attributes, UCHAR cp_type) {
  IKEv2_PACKET_PAYLOAD* payload = Ikev2CreatePacketPayload(IKEv2_CP_PAYLOAD_T, sizeof(IKEv2_CP_PAYLOAD));
  if (payload == NULL) {
    return NULL;
  }

  IKEv2_CP_PAYLOAD* cp = (IKEv2_CP_PAYLOAD*)payload->data;
  cp->type = cp_type;

  if (peer_conf != NULL) {
    cp->attributes = peer_conf->attributes;
  }
  else {
    cp->attributes = attributes;
  }
  return payload;
}

// ?
void Ikev2SendNotify(UINT64 SPIi, UINT64 SPIr, UINT msgID, IKEv2_PACKET_PAYLOAD* notify) {
  if (notify == NULL) {
    return;
  }
}

void Ikev2DeleteIKESA(IKEv2_SERVER* ike, IKEv2_SA* sa) {
  if (ike == NULL || sa == NULL) {
    return;
  }

  Dbg("Inside deleting IKE_SA");

  if (sa->isRekeyed == false) {
    LockList(ike->ipsec_SAs);
    UINT child_count = LIST_NUM(ike->ipsec_SAs);
    for (UINT i = 0; i < child_count; ++i) {
      IKEv2_IPSECSA* child = (IKEv2_IPSECSA*)LIST_DATA(ike->ipsec_SAs, i);
      if (child->ike_sa == sa) {
        Dbg("Deleting child_sa of IKE_SA");
        Delete(ike->ipsec_SAs, child);
        Ikev2FreeIPSECSA(child);

        child_count--;
        i--;
      }
    }
    UnlockList(ike->ipsec_SAs);
  }

  Delete(ike->SAs, sa);
  Ikev2FreeIKESA(sa);

  Dbg("IKE_SA deleted");
}

bool Ikev2DeleteChildSA(IKEv2_SERVER* ike, IKEv2_SA* parent, UINT SPI) {
  if (ike == NULL || parent == NULL) {
    return false;
  }

  Dbg("Inside deleting CHILD_SA");

  LockList(ike->ipsec_SAs);
  UINT sa_count = LIST_NUM(ike->ipsec_SAs);
  for (UINT i = 0; i < sa_count; ++i) {
    IKEv2_IPSECSA* sa = (IKEv2_IPSECSA*)LIST_DATA(ike->ipsec_SAs, i);
    if (sa->SPI == SPI && sa->ike_sa == parent) {
      Dbg("CHILD_SA found, freeing & deleting");
      Delete(ike->ipsec_SAs, sa);
      Ikev2FreeIPSECSA(sa);

      UnlockList(ike->ipsec_SAs);
      return true;
    }
  }

  UnlockList(ike->ipsec_SAs);
  Dbg("No child sa was deleted...");
  return false;
}

void ProcessIKEv2InformatinalExchange(IKEv2_SERVER *ike,IKEv2_PACKET* header, UDPPACKET *p) {
  if (header == NULL || ike == NULL || p == NULL) {
    return;
  }

  Dbg("INFORMATIONAL started");

  UINT64 SPIi = header->SPIi;
  UINT64 SPIr = header->SPIr;

  Dbg("INFORMATIONAL: getting IKE_SA with SPIs: %u, %u", SPIi, SPIr);
  IKEv2_SA* SA = Ikev2GetSABySPIAndClient(ike, SPIi, SPIr, NULL);
  if (SA == NULL) {
    Dbg("IKE_SA is not found!");
    return;
  }

  IKEv2_CRYPTO_PARAM* param = SA->param;

  IKEv2_PACKET* packet = Ikev2ParsePacket(header, p->Data, p->Size, param);
  if (packet == NULL) {
    Dbg("Can't parse packet");
    return;
  }

  IKEv2_PACKET_PAYLOAD* pSKi = Ikev2GetPayloadByType(packet->PayloadList, IKEv2_SK_PAYLOAD_T, 0);
  if (pSKi == NULL) {
    Dbg("Can't found SK payload");
    return;
  }

  IKEv2_SK_PAYLOAD* SKi = (IKEv2_SK_PAYLOAD*)pSKi->data;
  LIST* payloads = SKi->decrypted_payloads;

  Dbg("INFORMATIONAL: Payload count == %d", LIST_NUM(payloads));
  if (LIST_NUM(payloads) == 0) {
    Dbg("INFORMATIONAL: Got alive check, respond we are alive");

    LIST* empty = NewListFast(NULL);
    IKEv2_PACKET_PAYLOAD* sk = Ikev2CreateSK(empty, param);
    ReleaseList(empty);

    LIST* to_send = NewListSingle(sk);
    IKEv2_PACKET* np = Ikev2CreatePacket(SPIi, SPIr, IKEv2_INFORMATIONAL, true, false, false, packet->MessageId, to_send);
    Ikev2SendPacketByAddress(ike, &p->DstIP, p->DestPort, &p->SrcIP, p->SrcPort, np, param);

    Ikev2FreePacket(np);
    return;
  }

  LIST* to_send = NewList(NULL);

  bool needDeleteIKE = false;
  LIST* delete_payloads = Ikev2GetAllPayloadsByType(payloads, IKEv2_DELETE_PAYLOAD_T);
  UINT pay_count = LIST_NUM(delete_payloads);
  for (UINT i = 0; i < pay_count; ++i) {
    IKEv2_PACKET_PAYLOAD* pDel = (IKEv2_PACKET_PAYLOAD*)LIST_DATA(delete_payloads, i);
    IKEv2_DELETE_PAYLOAD* del = (IKEv2_DELETE_PAYLOAD*)pDel->data;
    Dbg("INFORMATIONAL: deleting proto id: %u, spi size %u, num_spi: %u", del->protocol_id, del->spi_size, del->num_spi);

    switch (del->protocol_id) {
      case IKEv2_DELETE_PROTO_IKE:
        Dbg("Need to delete IKE_SA");
        needDeleteIKE = true;
        break;
      case IKEv2_DELETE_PROTO_AH:
        Dbg("AH is not supported");
        break;
      case IKEv2_DELETE_PROTO_ESP: {
        Dbg("Deleting ESP CHILD_SA");
        USHORT spi_count = del->num_spi;
        for (USHORT j = 0; j < spi_count; ++j) {
          UINT SPI = ReadBufInt((BUF*)LIST_DATA(del->spi_list, j));
          bool res = Ikev2DeleteChildSA(ike, SA, SPI);
          if (res == true) {
            Add(to_send, pDel);
          }
        }
        break;
      }
      default:
        Dbg("Got unsupported protocol in delete: %u", del->protocol_id);
    }
  }

  IKEv2_PACKET_PAYLOAD* sk = Ikev2CreateSK(to_send, param);
  LIST* sk_list = NewListSingle(sk);

  IKEv2_PACKET* np = Ikev2CreatePacket(SPIi, SPIr, IKEv2_INFORMATIONAL, true, false, false, packet->MessageId, sk_list);
  UINT port = IPSEC_PORT_IPSEC_ISAKMP;
  if (SA->isClientBehindNAT == true) {
    Dbg("Sending packet through NAT");
    port = IPSEC_PORT_IPSEC_ESP_UDP;
  }
  Ikev2SendPacketByAddress(ike, &p->DstIP, port, &p->SrcIP, p->SrcPort, np, param);

  Dbg("INFORMATIONAL: Freeing informational exchange");
  Ikev2FreePacket(np);
  ReleaseList(to_send);

  if (needDeleteIKE == true) {
    Ikev2DeleteIKESA(ike, SA);
  }

  return;

  /* IKEv2_PACKET_PAYLOAD* notify_p = NULL; */
  /* int info_code_to_sent = Ikev2ProcessInformatonalPacket(header); */
  /* switch (info_code_to_sent) { */
  /* case INFO_EMPTY_REQUEST: */
  /* case INFO_EMPTY_RESPONSE: */
  /* //TODO second param is SPI */
  /* notify_p = Ikev2CreateNotify(IKEv2_NO_ERROR, NULL, NULL, false); */
  /* break; */
  /* [> case INFO_ERR_OCCURED: <] */
  /* [> // TODO change notification <] */
  /* [> notify_p = Ikev2CreateNotify(IKEv2_NO_ERROR, NULL, NULL, false); <] */
  /* [> break; <] */
  /* case INFO_VALID_NOTIFICATION: */
  /* notify_p = Ikev2CreateNotify(IKEv2_NO_ERROR, NULL, NULL, false); */
  /* break; */
  /* } */

  /* Dbg("Notify sending start"); */
  /* LIST *payloads = NewListSingle(notify_p); */
  /* IKEv2_PACKET* p = Ikev2CreatePacket(header->SPIi, header->SPIr, IKEv2_INFORMATIONAL, true, false, false, header->MessageId, payloads); */
  /* Ikev2SendPacketByAddress(ike, &p->DstIP, p->DestPort, &p->SrcIP, p->SrcPort, p); */
  /* IKEv2_PACKET_PAYLOAD* notification = Ikev2CreateNotify(IKEv2_INVALID_KE_PAYLOAD, NULL, error, false); */
  /* LIST* to_send = NewListSingle(notification); */
  /* IKEv2_PACKET* np = Ikev2CreatePacket(SPIi, 0, IKEv2_SA_INIT, true, false, false, packet->MessageId, to_send); */
  /* Ikev2SendPacketByAddress(ike, &p->DstIP, p->DestPort, &p->SrcIP, p->SrcPort, np, NULL); */

  /* Ikev2FreePacket(p); */
  /* ReleaseList(payloads); */
}

// Returns code of which notification we should send to peer
/* int Ikev2ProcessInformatonalPacket(IKEv2_PACKET *header) { */
/* // If empty request/response */
/* if (LIST_NUM(header->PayloadList) == 0) { */
/* if (header->FlagResponse) { */
/* if (header->MessageSize == 0) { */
/* // empty response is valid and tells that peer is alive */
/* return INFO_EMPTY_RESPONSE; */
/* } */
/* // TODO - DETACH DEAD PEERS - empty response is valid and tells that peer is alive */
/* } */
/* return INFO_EMPTY_REQUEST; */
/* } */

/* // TODO can be speed up by ONE iter over PayloadList with switch over types */

/* To properly proceed informational exchange need mechanism to
   * send responses right from here (because sometimes payload lists can
   * contain multiple payloads with different types and each one should
   * be answered at least with empty non-error notification). */
/* // Processing Delete */
/* LIST* payloads = Ikev2GetAllPayloadsByType(header->PayloadList, IKEv2_DELETE_PAYLOAD_T); */
/* assert(payloads); */
/* for (int i = 0; i < LIST_NUM(payloads); i++) { */
/* bool err_occurred = false; */
/* IKEv2_PACKET_PAYLOAD* payload = LIST_DATA(payloads, i); */

/* if (payload != NULL) { */
/* assert(payload->PayloadType == IKEv2_DELETE_PAYLOAD_T); */

/* // TODO not clear what to do here so be error */
/* if (payload->Payload.Delete.protocol_id == IKEv2_PROPOSAL_PROTOCOL_IKE || */
/* payload->Payload.Delete.protocol_id == IKEv2_PROPOSAL_PROTOCOL_ESP ) { */
/* err_occurred = true; */
/* } */
/* } */

/* Ikev2FreePayload(payload); */
/* if (err_occurred) { */
/* break; */
/* } */
/* } */
/* ReleaseList(payloads); */

/* // Notification */
/* payloads = Ikev2GetAllPayloadsByType(header->PayloadList, IKEv2_NOTIFY_PAYLOAD_T); */
/* assert(payloads); */
/* for (int i = 0; i < LIST_NUM(payloads); i++) { */
/* IKEv2_PACKET_PAYLOAD* payload = LIST_DATA(payloads, i); */
/* if (payload != NULL) { */
/* assert(payload->PayloadType == IKEv2_NOTIFY_PAYLOAD_T); */

/* USHORT err_code = Ikev2GetNotificationErrorCode(payload->Payload.Notify.notification_type); */
/* switch (err_code) { */
/* case IKEv2_UNSUPPORTED_CRITICAL_PAYLOAD: */
/* case IKEv2_INVALID_SYNTAX: */
/* case IKEv2_AUTHENTICATION_FAILED: */
/* [> TODO: Delete the IKE SA in that case <] */
/* // Ikev2DeleteSAWithInformational(header->SPIi, header->SPIr); */
/* break; */
/* case IKEv2_NO_ERROR: */
/* Dbg("INFORMATIONAL: unhandled NOTIFY with type %d", payload->Payload.Notify.notification_type); */
/* break; // TODO WHAT should be returned - dunno */
/* } */
/* Ikev2FreePayload(payload); */
/* } */
/* } */
/* ReleaseList(payloads); */

/* // Configuration */
/* // TODO processing */
/* payloads = Ikev2GetAllPayloadsByType(header->PayloadList, IKEv2_CP_PAYLOAD_T); */
/* for (int i = 0; i < LIST_NUM(payloads); i++) { */
/* IKEv2_PACKET_PAYLOAD* payload = LIST_DATA(payloads, i); */
/* if (payload != NULL) { */
/* assert(payload->PayloadType == IKEv2_CP_PAYLOAD_T); */

/* ReleaseList(payloads); */
/* return INFO_VALID_NOTIFICATION; */
/* } */
/* } */

/* ReleaseList(payloads); */
/* return INFO_ERR_OCCURED; */
/* } */

bool IKEv2SetKeymatFromSKEYSEED(IKEv2_CRYPTO_KEY_DATA* key_data, IKEv2_PRF* prf, void* skeyseed,
                                BUF* nonce_i, BUF* nonce_r, UINT64 SPIi, UINT64 SPIr) {

  UINT nonce_sum_size = nonce_i->Size + nonce_r->Size;

  UCHAR* newText = ZeroMalloc(nonce_sum_size + sizeof(UCHAR) * 16);
  Copy(newText, nonce_i->Buf, nonce_i->Size);
  Copy(newText + nonce_i->Size, nonce_r->Buf, nonce_r->Size);

  UINT64 EndianSPIi = Endian64(SPIi);
  UINT64 EndianSPIr = Endian64(SPIr);
  Copy(newText + nonce_sum_size, &EndianSPIi, 8);
  Copy(newText + nonce_sum_size + 8, &EndianSPIr, 8);

  UINT needed_size = 3 * prf->key_size + 2 * key_data->encr_key_size + 2 * key_data->integ_key_size;
  UCHAR* keying_mat = Ikev2CalcPRFplus(prf, skeyseed, key_data->prf_key_size, newText, nonce_sum_size + 16, needed_size);
  Free(newText);

  if (keying_mat == NULL) {
    Debug("Keymat PRF+ calc failed...\n");
    return false;
  }

  Dbg("Saving keying mat");
  key_data->sk_d = keying_mat;
  //DbgPointer("sk_d", key_data->sk_d, key_data->prf_key_size);

  UINT offset = 0;
  offset += key_data->prf_key_size;
  key_data->sk_ai = keying_mat + offset;
  //DbgPointer("sk_ai", key_data->sk_ai, key_data->integ_key_size);

  offset += key_data->integ_key_size;
  key_data->sk_ar = keying_mat + offset;
  //DbgPointer("sk_ar", key_data->sk_ar, key_data->integ_key_size);

  offset += key_data->integ_key_size;
  key_data->sk_ei = keying_mat + offset;
  //DbgPointer("sk_ei", key_data->sk_ei, key_data->encr_key_size);

  offset += key_data->encr_key_size;
  key_data->sk_er = keying_mat + offset;
  //DbgPointer("sk_er", key_data->sk_er, key_data->encr_key_size);

  offset += key_data->encr_key_size;
  key_data->sk_pi = keying_mat + offset;
  //DbgPointer("sk_pi", key_data->sk_pi, key_data->prf_key_size);

  offset += key_data->prf_key_size;
  key_data->sk_pr = keying_mat + offset;
  //DbgPointer("sk_pr", key_data->sk_pr, key_data->prf_key_size);

  return true;
}

void* IKEv2GenerateSKEYSEEDInitial(IKEv2_PRF* prf, BUF *nonce_i, BUF *nonce_r, UCHAR *shared_key, UINT key_len) {
  if (prf == NULL || nonce_i == NULL || nonce_r == NULL || shared_key == NULL) {
    return NULL;
  }

  UINT nonce_sum_size = nonce_i->Size + nonce_r->Size;
  if (nonce_sum_size < prf->key_size) {
    Debug("Nonces are not long enough\n");
    return NULL;
  }

  UCHAR* nonce_concat = ZeroMalloc(sizeof(UCHAR) * nonce_sum_size);
  Copy(nonce_concat, nonce_i->Buf, nonce_i->Size);
  Copy(nonce_concat + nonce_i->Size, nonce_r->Buf, nonce_r->Size);

  UCHAR* skeyseed = Ikev2CalcPRF(prf, nonce_concat, nonce_sum_size, shared_key, sizeof(UCHAR) * key_len);
  if (skeyseed == NULL) {
    Dbg("Error in generating SKEYSEED");
  }/*
  else {
    DbgPointer("SKEYSEED", skeyseed, prf->key_size);
  }*/

  Free(nonce_concat);
  return skeyseed;
}

void* IKEv2GenerateSKEYSEEDRekeyIKESA(IKEv2_PRF* prf, UCHAR* sk_d, UINT len_sk_d,
                                      BUF* nonce_i, BUF* nonce_r, UCHAR* shared_key, UINT key_len) {
  if (prf == NULL || nonce_i == NULL || nonce_r == NULL || shared_key == NULL) {
    return NULL;
  }

  UINT key_sum_size = key_len + nonce_i->Size + nonce_r->Size;
  if (key_sum_size < prf->key_size) {
    Debug("Nonces are not long enough\n");
    return NULL;
  }

  UCHAR* nonce_concat = ZeroMalloc(sizeof(UCHAR) * key_sum_size);
  Copy(nonce_concat, shared_key, key_len);
  Copy(nonce_concat + key_len, nonce_i->Buf, nonce_i->Size);
  Copy(nonce_concat + nonce_i->Size + key_len, nonce_r->Buf, nonce_r->Size);
  DbgPointer("Nonce concat", nonce_concat, key_sum_size);

  Dbg("Calc PRF");
  UCHAR* skeyseed = Ikev2CalcPRF(prf, sk_d, len_sk_d, nonce_concat, key_sum_size);
  if (skeyseed == NULL) {
    Dbg("Error in generating SKEYSEED");
  }
  else {
    DbgPointer("SKEYSEED", skeyseed, prf->key_size);
  }

  Free(nonce_concat);
  return skeyseed;
}

IKEv2_CRYPTO_KEY_DATA* IKEv2GenerateKeymatForIKESA(IKEv2_CRYPTO_SETTING* setting, IKEv2_PRF* prf, BUF *nonce_i, BUF *nonce_r,
                                                   UCHAR *shared_key, UINT key_len, UINT64 SPIi, UINT64 SPIr, void* sk_d, UINT len_sk_d, bool isInitial) {

  if (setting == NULL || nonce_i == NULL || nonce_r == NULL || shared_key == NULL) {
    return NULL;
  }

  Dbg("Generating initial keying material");
  IKEv2_CRYPTO_KEY_DATA* key_data = ZeroMalloc(sizeof(IKEv2_CRYPTO_KEY_DATA));

  key_data->encr_key_size = setting->key_size;
  key_data->prf_key_size = setting->prf->key_size;
  key_data->integ_key_size = setting->integ->key_size;
  key_data->shared_key = shared_key;
  Dbg("key sizes set");
  key_data->IV = NULL;

  key_data->aes_key_e = key_data->aes_key_d = NULL;
  key_data->des_key_e = key_data->des_key_d = NULL;
  key_data->des3_key_e = key_data->des3_key_d = NULL;

  void* skeyseed = (isInitial == true) ? IKEv2GenerateSKEYSEEDInitial(prf, nonce_i, nonce_r, shared_key, key_len) :
                   IKEv2GenerateSKEYSEEDRekeyIKESA(prf, sk_d, len_sk_d, nonce_i, nonce_r, shared_key, key_len);
  if (skeyseed == NULL) {
    Dbg("Keymat failed, SKEYSEED == NULL");
    Free(key_data);
    return NULL;
  }

  bool res = IKEv2SetKeymatFromSKEYSEED(key_data, prf, skeyseed, nonce_i, nonce_r, SPIi, SPIr);
  if (res == false) {
    Dbg("Keymat is not generated");
    Free(key_data);
    key_data = NULL;
  }

  Free(skeyseed);
  return key_data;
}

UINT64 Ikev2CreateSPI(IKEv2_SERVER *ike) {
  UINT64 res = Rand64();

  while (1) {
    bool ok = (res == 0) ? false : true;

    if (ok == true) {
      UINT SA_count = LIST_NUM(ike->SAs);
      for (UINT i = 0; i < SA_count; ++i) {
        IKEv2_SA* SA = (IKEv2_SA*)LIST_DATA(ike->SAs, i);
        if (SA->SPIr == res) {
          ok = false;
          break;
        }
      }
    }

    if (ok == true) {
      break;
    }

    res = Rand64();
  }

  return res;
}

DH_CTX* Ikev2CreateDH_CTX(IKEv2_DH* dh) {
  if (dh == NULL) {
    return NULL;
  }

  switch (dh->type)
  {
    case IKEv2_TRANSFORM_ID_DH_NONE:
      return NULL;
    case IKEv2_TRANSFORM_ID_DH_768:
      return DhNew(DH_GROUP1_PRIME_768, 2);
    case IKEv2_TRANSFORM_ID_DH_1024:
      return DhNew(DH_GROUP2_PRIME_1024, 2);
    case IKEv2_TRANSFORM_ID_DH_1536:
      return DhNew(DH_GROUP5_PRIME_1536, 2);
    case IKEv2_TRANSFORM_ID_DH_2048:
      return DhNew(DH_SET_2048, 2);
    case IKEv2_TRANSFORM_ID_DH_3072:
      return DhNew(DH_SET_3072, 2);
    case IKEv2_TRANSFORM_ID_DH_4096:
      return DhNew(DH_SET_4096, 2);
    case IKEv2_TRANSFORM_ID_DH_6144:
      return DhNew(DH_SET_6144, 2);
    case IKEv2_TRANSFORM_ID_DH_8192:
      return DhNew(DH_SET_8192, 2);
    default:
      break;
  }

  return NULL;
}

IKEv2_ENCR* Ikev2CreateEncr(UCHAR type, bool is_fixed, UINT* key_sizes, UINT key_count, UINT min_key, UINT max_key, UINT default_key, UINT block_size){
  IKEv2_ENCR* ret = ZeroMalloc(sizeof(IKEv2_ENCR));

  ret->type = type;
  ret->is_fixed = is_fixed;
  if (is_fixed == true) {
    ret->key_info.fixed.key_sizes = Malloc(sizeof(UINT) * key_count);
    for (UINT i = 0; i < key_count; ++i) {
      ret->key_info.fixed.key_sizes[i] = key_sizes[i];
    }
    ret->key_info.fixed.key_count = key_count;
  }
  else {
    ret->key_info.range.min_key_len = min_key;
    ret->key_info.range.max_key_len = max_key;
    ret->key_info.range.default_key = default_key;
  }
  ret->block_size = block_size;

  return ret;
}

IKEv2_PRF* Ikev2CreatePRF(UCHAR type, UINT key_size) {
  IKEv2_PRF* ret = ZeroMalloc(sizeof(IKEv2_PRF));

  ret->type = type;
  ret->key_size = key_size;

  return ret;
}

IKEv2_INTEG* Ikev2CreateInteg(UCHAR type, UINT key_size, UINT out_size) {
  IKEv2_INTEG* ret = ZeroMalloc(sizeof(IKEv2_INTEG));

  ret->type = type;
  ret->key_size = key_size;
  ret->out_size = out_size;

  return ret;
}

IKEv2_DH* Ikev2CreateDH(UCHAR type, UINT size) {
  IKEv2_DH* ret = ZeroMalloc(sizeof(IKEv2_DH));

  ret->type = type;
  ret->size = size;

  return ret;
}

IKEv2_ENCR* Ikev2GetEncr(IKEv2_CRYPTO_ENGINE* engine, USHORT type) {
  if (engine == NULL) {
    return NULL;
  }

  return engine->ike_encr[type];
}

IKEv2_PRF* Ikev2GetPRF(IKEv2_CRYPTO_ENGINE* engine, USHORT type) {
  if (engine == NULL) {
    return NULL;
  }

  return engine->ike_prf[type];
}

IKEv2_INTEG* Ikev2GetInteg(IKEv2_CRYPTO_ENGINE* engine, USHORT type) {
  if (engine == NULL) {
    return NULL;
  }

  return engine->ike_integ[type];
}

IKEv2_DH* Ikev2GetDH(IKEv2_CRYPTO_ENGINE* engine, USHORT type) {
  if (engine == NULL) {
    return NULL;
  }

  return engine->ike_dh[type];
}

void* Ikev2CalcPRF(IKEv2_PRF* prf, void* key, UINT key_size, void* text, UINT text_size) {
  assert(prf != NULL && key != NULL && text != NULL);

  UCHAR* ret = (UCHAR*)Malloc(sizeof(UCHAR) * prf->key_size);

  switch (prf->type){
    case IKEv2_TRANSFORM_ID_PRF_HMAC_MD5:
      HMacMd5(ret, key, key_size, text, text_size);
      break;
    case IKEv2_TRANSFORM_ID_PRF_HMAC_SHA1:
      HMacSha1(ret, key, key_size, text, text_size);
      break;
    default:
      Debug("Unknown prf type: u\n", prf->type);
      Free(ret);
      ret = NULL;
  }

  return ret;
}

void* Ikev2CalcPRFplus(IKEv2_PRF* prf, void* key, UINT key_size, void* text, UINT text_size, UINT needed_size) {
  assert(prf != NULL && key != NULL && text != NULL);

  UINT iteration_num = needed_size / prf->key_size;
  if ((needed_size % prf->key_size) > 0) {
    iteration_num++;
  }

  UCHAR* ret = (UCHAR*)ZeroMalloc((iteration_num * prf->key_size) * sizeof(UCHAR));
  void* last = NULL;
  for (UCHAR i = 0; i < iteration_num; ++i) {
    BUF* new_text = NewBuf();
    if (i > 0) {
      WriteBuf(new_text, last, prf->key_size);
    }
    WriteBuf(new_text, text, text_size);
    WriteBufChar(new_text, i + 1);

    void* prf_ret = Ikev2CalcPRF(prf, key, key_size, new_text->Buf, new_text->Size);
    if (prf_ret == NULL) {
      Debug("PRF+ calculation error - ret == NULL\n");
      break;
    }

    Copy(ret + (UINT)i * (prf->key_size), prf_ret, prf->key_size * sizeof(UCHAR));

    FreeBuf(new_text);
    if (last != NULL) {
      Free(last);
    }
    last = prf_ret;
  }

  if (last != NULL) {
    Free(last);
  }

  return ret;
}

void* Ikev2CalcInteg(IKEv2_INTEG* integ, void* key, void* text, UINT text_size) {
  assert(integ != NULL && key != NULL && text != NULL);

  UCHAR* ret = (UCHAR*)ZeroMalloc(sizeof(UCHAR) * integ->out_size);
  switch (integ->type) {
    case IKEv2_TRANSFORM_ID_AUTH_HMAC_MD5_96: {
      void* tempDst = ZeroMalloc(MD5_HASH_SIZE);
      HMacMd5(tempDst, key, integ->key_size, text, text_size);
      Copy(ret, tempDst, integ->out_size);
      break;
    }
    case IKEv2_TRANSFORM_ID_AUTH_HMAC_SHA1_96:
      MacSha196(ret, key, text, text_size);
      break;
    case IKEv2_TRANSFORM_ID_AUTH_AES_XCBC_96:
    case IKEv2_TRANSFORM_ID_AUTH_NONE:
      Debug("No specification for this algo: %u", integ->type);
      break;
    default:
      Debug("Unknown integrity function: %u\n", integ->type);
      Free(ret);
      return NULL;
  }

  return ret;
}

void Ikev2SendData(IKEv2_SERVER* s, IP* srcIP, UINT srcPort, IP* destIP, UINT destPort, UCHAR* data, UINT size, USHORT type) {
  if (s == NULL || data == NULL) {
    return;
  }

  UDPPACKET* udp = NewUdpPacket(srcIP, srcPort, destIP, destPort, data, size);
  udp->Type = type;

  Add(s->SendPacketList, udp);
}

void Ikev2SendPacket(IKEv2_SERVER* s, IKEv2_CLIENT* client, IKEv2_PACKET* p, IKEv2_CRYPTO_PARAM* param) {
  if (s == NULL || p == NULL) {
    return;
  }

  Ikev2SendPacketByAddress(s, &client->server_ip, client->server_port, &client->client_ip, client->client_port, p, param);
}

void Ikev2SendPacketByAddress(IKEv2_SERVER* s, IP* srcIP, UINT srcPort, IP* destIP, UINT destPort, IKEv2_PACKET* p, IKEv2_CRYPTO_PARAM* param) {
  if (s == NULL || p == NULL) {
    return;
  }

  Dbg("Building packet for sending...");
  BUF* buf = Ikev2BuildPacket(p); // MUST BE NOT FREED
  if (buf == NULL) {
    Dbg("Packet is not built");
    return;
  }
  if (param != NULL) {
    // SK found
    void* integ = Ikev2CalcInteg(param->setting->integ, param->key_data->sk_ar, buf->Buf, buf->Size);
    BUF* ret = MemToBuf(integ, param->setting->integ->out_size);
    WriteBufBuf(buf, ret);
    p->ByteMsg = CloneBuf(buf);

    //param->key_data->IV = ((IKEv2_PACKET_PAYLOAD*)LIST_DATA(p->PayloadList, 0))->Payload.SK.init_vector->Buf;
    //param->key_data->des3_key_d = NULL;
    //param->key_data->aes_key_d = NULL;
    //param->key_data->des_key_d = NULL;
    //param->key_data->sk_ei = param->key_data->sk_er;
    //param->key_data->sk_ai = param->key_data->sk_ar;
    ////BUF* decr = Ikev2Decrypt(buf->Buf, buf->Size, param);
    ////param->key_data->IV = NULL;

    //UDPPACKET* udp = NewUdpPacket(srcIP, srcPort, destIP, destPort, buf->Buf, buf->Size);
    //ProcessIKEv2AuthExchange(s, udp);
    //Dbg("Exit from recursion run...");
  }

  Dbg("Packet built, creating UDPPACKET, destPort = %u", destPort);
  UDPPACKET* udp = NewUdpPacket(srcIP, srcPort, destIP, destPort, buf->Buf, buf->Size);
  if (udp == NULL) {
    Dbg("UDP packet is NULL");
    return;
  }
  udp->Type = IKE_UDP_TYPE_ISAKMP;

  Dbg("UDP ready, set to send list on server");
  Add(s->SendPacketList, udp);
}

IKEv2_PACKET_PAYLOAD* Ikev2CreateEAP(UCHAR code, UCHAR id, UCHAR type, BUF* type_data) {
  IKEv2_PACKET_PAYLOAD* payload = Ikev2CreatePacketPayload(IKEv2_EAP_PAYLOAD_T, sizeof(IKEv2_EAP_PAYLOAD));
  if (payload == NULL) {
    Dbg("error: failed to allocate mem ");
    return NULL;
  }

  USHORT len = 4;
  IKEv2_EAP_PAYLOAD* m = (IKEv2_EAP_PAYLOAD*)payload->data;
  m->code = code;
  m->identifier = id;
  if (m->code == 1 || m->code == 2) {
    m->type = type;
    m->type_data = CloneBuf(type_data);
    len += 1 + (USHORT)type_data->Size;
  }
  m->length = len;

  return payload;
}

IKEv2_IPSECSA* Ikev2FindIPSECSA(IKEv2_SERVER* ike, UINT SPI) {
  if (ike == NULL) {
    return NULL;
  }

  UINT childSACount = LIST_NUM(ike->ipsec_SAs);
  for (UINT i = 0; i < childSACount; ++i) {
    IKEv2_IPSECSA* child = (IKEv2_IPSECSA*)LIST_DATA(ike->ipsec_SAs, i);
    if (child->isClosed == false && child->SPI == SPI) {
      return child;
    }
  }

  return NULL;
}
