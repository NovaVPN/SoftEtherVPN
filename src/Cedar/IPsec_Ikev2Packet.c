#include <assert.h>

#include "IPsec_Ikev2Packet.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

/*
* Assumptions:
*  snake_case function names are for protocol, wrapper
*  functions are in CamelCase to distinct each other.
*
*  error code passed in argument list and should be
*  checked in wrappers to respond client properly.*/

/*                   SA PAYLOAD                       */
BUF* ikev2_SA_encode(IKEv2_SA_PAYLOAD *p) {
	if (p == NULL) {
		return NULL;
	}

	BUF* b = NewBuf();

	UINT len = LIST_NUM(p->proposals);
	for (UINT i = 0; i < len; ++i) {
		IKEv2_SA_PROPOSAL *prop = (IKEv2_SA_PROPOSAL*)LIST_DATA(p->proposals, i);

		BUF* tb = NewBuf();
		for (UCHAR j = 0; j < prop->transform_number; ++j) {
			// Encoding transform into tb and write it into b
			IKEv2_SA_TRANSFORM *t = (IKEv2_SA_TRANSFORM*)LIST_DATA(prop->transforms, j);
			BUF* tpb = NewBuf();

			UINT attributes_len = LIST_NUM(t->attributes);
			for (UINT attrIndex = 0; attrIndex < attributes_len; ++attrIndex) {
				IKEv2_TRANSFORM_ATTRIBUTE *attr = (IKEv2_TRANSFORM_ATTRIBUTE*)LIST_DATA(t->attributes, attrIndex);
				USHORT attrType = attr->type;
				if (attr->format == 1) {
					attrType |= (USHORT)(1 << 15);
				}

				WriteBufShort(tpb, attrType);
				WriteBufShort(tpb, attr->value);

				if (attr->format == 0) {
					WriteBufBuf(tpb, attr->TLV_value);
				}
			}

			WriteBufChar(tb, (UCHAR)((t->is_last == false) ? 3 : 0));

			//reserve & skip length for now
			WriteBufChar(tb, (UCHAR)0);
			WriteBufShort(tb, (USHORT)tpb->Size+8);

			WriteBufChar(tb, t->transform.type);
			WriteBufChar(tb, (UCHAR)0);
			WriteBufShort(tb, t->transform.ID);

			WriteBufBuf(tb, tpb);
			FreeBuf(tpb);
		}

		BUF *pb = NewBuf();
		// Encode proposal
		WriteBufChar(pb, (UCHAR)((prop->is_last == false) ? 2 : 0));
		WriteBufChar(pb, (UCHAR)0);

		// skip proposal_length now
		// header size offset
		WriteBufShort(pb, (USHORT)tb->Size + 8 + prop->SPI_size);

		WriteBufChar(pb, prop->number); // proposal number
		WriteBufChar(pb, prop->protocol_id);
		WriteBufChar(pb, prop->SPI_size);
		WriteBufChar(pb, prop->transform_number);
		if (prop->SPI_size > 0) {
			WriteBufBuf(pb, prop->SPI);
		}

		WriteBufBuf(pb, tb);
		// Proposal encoded, now write data into buffer
		WriteBufBuf(b, pb);
		FreeBuf(pb);
	}

	return b;
}

UINT ikev2_SA_decode(BUF *b, IKEv2_SA_PAYLOAD *p) {
	p->proposals = NewListFast(NULL);
	bool isLastProposal = (b->Size == 0) ? true : false;
	while (!isLastProposal) {
		IKEv2_SA_PROPOSAL *proposal = (IKEv2_SA_PROPOSAL*)Malloc(sizeof(IKEv2_SA_PROPOSAL));
		if (proposal == NULL) {
			ikev2_free_SA_payload(p);
			Dbg("Error while allocate memory for SA_PROPOSAL");
			return IKEv2_OUT_OF_MEMORY;
		}

		UCHAR isLast = ReadBufChar(b);
		proposal->is_last = (isLast > 0) ? false : true;
		ReadBufChar(b);

		proposal->length = ReadBufShort(b);
		proposal->number = ReadBufChar(b);
		proposal->protocol_id = ReadBufChar(b);
		proposal->SPI_size = ReadBufChar(b);
		proposal->transform_number = ReadBufChar(b);
		
		if (proposal->SPI_size > 0) {
			proposal->SPI = ReadBufFromBuf(b, proposal->SPI_size);
		}
		else {
			proposal->SPI = NULL;
		}

		proposal->transforms = NewListFast(NULL);
		for (UCHAR i = 0; i < proposal->transform_number; ++i) {
			IKEv2_SA_TRANSFORM *t = (IKEv2_SA_TRANSFORM*)ZeroMalloc(sizeof(IKEv2_SA_TRANSFORM));
			if (t == NULL) {
				ikev2_free_SA_payload(p);
				Dbg("Error while allocate memory for SA_TRANSFORM");
				return IKEv2_OUT_OF_MEMORY;
			}

			UCHAR last = ReadBufChar(b);
			t->is_last = (last > 0) ? false : true;
			ReadBufChar(b);
			t->transform_length = ReadBufShort(b);
			t->transform.type = ReadBufChar(b);
			ReadBufChar(b);
			t->transform.ID = ReadBufShort(b);

			t->attributes = NewListFast(NULL);
			USHORT len = t->transform_length-8;
			while (len > 0) {
				IKEv2_TRANSFORM_ATTRIBUTE *attr = (IKEv2_TRANSFORM_ATTRIBUTE*)ZeroMalloc(sizeof(IKEv2_TRANSFORM_ATTRIBUTE));
				if (attr == NULL) {
					ikev2_free_SA_payload(p);
					Dbg("Can't allocate memory for TRANSFORM_ATTRIBUTE");
					return IKEv2_OUT_OF_MEMORY;
				}

				USHORT attrType = ReadBufShort(b);
				attr->format = ((attrType & (1 << 15)) > 0) ? 1 : 0;
				attr->type = attrType & ((1 << 15) - 1);
				attr->value = ReadBufShort(b);
				len -= 4;
				if (attr->format == 0) {
					attr->TLV_value = ReadBufFromBuf(b, attr->value);
					len -= attr->TLV_value->Size;
				}

				Add(t->attributes, (void*)attr);
			}
			if (len != 0) {
				return IKEv2_INVALID_SYNTAX;
			}

			Add(proposal->transforms, (void*)t);
		}

		Add(p->proposals, (void*)proposal);
		isLastProposal = isLast ^ 2;
	}

    return IKEv2_NO_ERROR;
}

void ikev2_free_SA_transform(IKEv2_SA_TRANSFORM *t) {
	if (t == NULL) {
		return;
	}

	UINT attrCount = LIST_NUM(t->attributes);
	for (UINT k = 0; k < attrCount; ++k) {
		IKEv2_TRANSFORM_ATTRIBUTE* attr = LIST_DATA(t->attributes, k);

		if (attr->TLV_value != NULL) {
			FreeBuf(attr->TLV_value);
		}
		Free(attr);
		attr = NULL;
	}

	ReleaseList(t->attributes);
	Free(t);
}

void ikev2_free_SA_payload(IKEv2_SA_PAYLOAD *p) {
	if (p == NULL) {
		return;
	}

	for (UINT i = 0; i < LIST_NUM(p->proposals); i++) {
		IKEv2_SA_PROPOSAL* prop = LIST_DATA(p->proposals, i);

		UINT transformCount = LIST_NUM(prop->transforms);
		for (UINT j = 0; j < transformCount; ++j) {
			IKEv2_SA_TRANSFORM* transform = LIST_DATA(prop->transforms, j);
			ikev2_free_SA_transform(transform);
		}

		FreeBuf(prop->SPI);
		ReleaseList(prop->transforms);
		Free(prop);
		prop = NULL;
	}

	ReleaseList(p->proposals);
	Free(p);
}
/*                END SA PAYLOAD                      */

/*                   KE PAYLOAD                       */
BUF* ikev2_KE_encode(IKEv2_KE_PAYLOAD *p) {
	if (p == NULL) {
		return NULL;
	}

	BUF* b = NewBuf();

	WriteBufShort(b, p->DH_transform_ID);
	// Offset 2 bytes
	WriteBufShort(b, (USHORT)0);
	WriteBufBuf(b, p->key_data);

	return b;
}

UINT ikev2_KE_decode(BUF *b, IKEv2_KE_PAYLOAD* p) {
	assert(b);
	// There must be key_data with size >= 1
	if (b->Size < sizeof(USHORT) * 2 + 1) {
		Debug("KE payload bytes is too short: %d, expected more than 4 bytes\n", b->Size);
		return IKEv2_INVALID_SYNTAX;
	}
	p->DH_transform_ID = ReadBufShort(b);
	ReadBufShort(b); // RESERVED field, skip
	p->key_data = ReadRemainBuf(b);

	return IKEv2_NO_ERROR;
}

void ikev2_free_KE_payload(IKEv2_KE_PAYLOAD *p) {
	if (p == NULL) {
		return;
	}

	FreeBuf(p->key_data);
	Free(p);
}
/*                 END KE PAYLOAD                     */

/*                   ID PAYLOAD                       */
BUF* ikev2_ID_encode(IKEv2_ID_PAYLOAD *p) {
	if (p == NULL) {
		return NULL;
	}

	BUF* b = NewBuf();

	WriteBufChar(b, p->ID_type);
	// Offset 3 bytes
	WriteBufShort(b, 0);
	WriteBufChar(b, 0);
	WriteBufBuf(b, p->data);

	return b;
}

UINT ikev2_ID_decode(BUF *b, IKEv2_ID_PAYLOAD* p) {
	assert(b);

	if (b->Size < sizeof(USHORT) * 2) {
		Debug("ID payload bytes is too short: %d, expected more than 3 bytes\n", b->Size);
		return IKEv2_INVALID_SYNTAX;
	}
	p->ID_type = ReadBufChar(b);

	// skip reserved
	ReadBufShort(b);
	ReadBufChar(b);

	p->data = ReadRemainBuf(b);
	return IKEv2_NO_ERROR;
}

void ikev2_free_ID_payload(IKEv2_ID_PAYLOAD *p) {
	if (p == NULL || p->data == NULL) {
		return;
	}

	FreeBuf(p->data);
	Free(p);
}
/*                 END ID PAYLOAD                     */

/*                 CERT PAYLOAD                       */
BUF* ikev2_cert_encode(IKEv2_CERT_PAYLOAD* p) {
	if (p == NULL) {
		return NULL;
	}

	BUF* b = NewBuf();

	WriteBufChar(b, p->encoding_type);
	WriteBufBuf(b, p->data);

	return b;
}

UINT ikev2_cert_decode(BUF* b, IKEv2_CERT_PAYLOAD *p) {
	assert(b);
	if (b->Size < sizeof(UCHAR) + 1) {
		return IKEv2_INVALID_SYNTAX;
	}

	p->encoding_type = ReadBufChar(b);
	p->data = ReadRemainBuf(b); // check buf_size in caller function

	return IKEv2_NO_ERROR;
}

void ikev2_free_cert_payload(IKEv2_CERT_PAYLOAD* p) {
	if (p == NULL) {
		return;
	}
	FreeBuf(p->data);
	Free(p);
}
/*               END CERT PAYLOAD                     */

/*                 CERT_REQ PAYLOAD                       */
BUF* ikev2_cert_req_encode(IKEv2_CERTREQ_PAYLOAD* p) {
	return ikev2_cert_encode((IKEv2_CERT_PAYLOAD*)p);
}

UINT ikev2_cert_req_decode(BUF* b, IKEv2_CERTREQ_PAYLOAD *p) {
	return ikev2_cert_decode(b, p);
}

void ikev2_free_cert_req_payload(IKEv2_CERTREQ_PAYLOAD* p) {
	ikev2_free_cert_payload((IKEv2_CERT_PAYLOAD*)p);
}
/*               END CERT_REQ PAYLOAD                     */

/*                   AUTH PAYLOAD                     */
BUF* ikev2_auth_encode(IKEv2_AUTH_PAYLOAD *a) {
	BUF* b = NewBuf();

	WriteBufChar(b, a->auth_method);
	// reserved offset 3 bytes
	WriteBufShort(b, 0);
	WriteBufChar(b, 0);

	WriteBufBuf(b, a->data);

	return b;
}

UINT ikev2_auth_decode(BUF *b, IKEv2_AUTH_PAYLOAD *auth) {
	assert(b);

	if (b->Size < sizeof(UCHAR) + 3) {
		Debug("IKEv2 auth decode error: size of received buffer is %d\n", b->Size);
		return IKEv2_INVALID_SYNTAX;
	}

	auth->auth_method = ReadBufChar(b);
	//skip reserved
	ReadBufShort(b);
	ReadBufChar(b);

	auth->data = ReadRemainBuf(b);
	return IKEv2_NO_ERROR;
}

void ikev2_free_auth_payload(IKEv2_AUTH_PAYLOAD *p) {
	if (p == NULL) {
		return;
	}

	FreeBuf(p->data);
	Free(p);
}
/*                END AUTH PAYLOAD                    */

/*                NONCE PAYLOAD                       */
BUF* ikev2_nonce_encode(IKEv2_NONCE_PAYLOAD *p) {
	BUF * b = NewBuf();
	WriteBufBuf(b, p->nonce);
	return b;
}

UINT ikev2_nonce_decode(BUF *b, IKEv2_NONCE_PAYLOAD *p) {
	// Nonce is more than 16 and less than 256 octets
	assert(b && p);

	if (b->Size < IKEv2_MIN_NONCE_SIZE || b->Size > IKEv2_MAX_NONCE_SIZE) {
		return IKEv2_INVALID_SYNTAX;
	}

	p->nonce = CloneBuf(b);
	return IKEv2_NO_ERROR;
}

void ikev2_free_nonce_payload(IKEv2_NONCE_PAYLOAD *p) {
	if (p == NULL) {
		return;
	}

	FreeBuf(p->nonce);
	Free(p);
}
/*              END NONCE PAYLOAD                     */

/*               NOTIFY PAYLOAD                       */
BUF* ikev2_notify_encode(IKEv2_NOTIFY_PAYLOAD *p) {
    assert(p);

    BUF* b = NewBuf();
    WriteBufChar(b, p->protocol_id);
    WriteBufChar(b, p->spi_size);
    WriteBufShort(b, p->notification_type);
    if (p->spi_size > 0) {
      WriteBufBuf(b, p->spi);
    }

    switch (p->notification_type) {
        // TODO seems like that is only one payload type with specific processing, figure out
		case IKEv2_INVALID_KE_PAYLOAD:
			WriteBufShort(b, ReadBufShort(p->message));
			break;
		case IKEv2_NAT_DETECTION_DESTINATION_IP:
		case IKEv2_NAT_DETECTION_SOURCE_IP:
        default:
            WriteBufBuf(b, p->message);
    }
    return b;
}

UINT ikev2_notify_decode(BUF *b, IKEv2_NOTIFY_PAYLOAD *p) {
	assert(b && p);

	if (b->Size < sizeof(USHORT) + 2 * sizeof(UCHAR)) {
		return IKEv2_INVALID_SYNTAX;
	}

	p->protocol_id = ReadBufChar(b);
	p->spi_size = ReadBufChar(b);
	p->notification_type = ReadBufShort(b);
	Dbg("NOTIFY: type = %u", p->notification_type);

	UCHAR offset = 4; // offset of protocol_id, spi_size, notification_type
	if (b->Size < offset + p->spi_size) {
		return IKEv2_INVALID_SYNTAX;
	}

	p->spi = ReadBufFromBuf(b, p->spi_size);

	BUF *data = ReadRemainBuf(b);
	switch (p->notification_type) {
	case IKEv2_INVALID_KE_PAYLOAD:
		if (data->Size != 2) {
			Debug("Invalid syntax: NOTIFY_PAYLOAD - INVALID_KE_PAYLOAD\n");
			return IKEv2_INVALID_SYNTAX;
		}
		WriteBufShort(p->message, ReadBufShort(data));
		break;
	case IKEv2_COOKIE:
		if (data->Size == 0 || data->Size > 64) {
			Debug("Invalid syntax: NOTIFY_PAYLOAD - COOKIE wrong size\n");
			return IKEv2_INVALID_SYNTAX;
		}
		p->message = data;
		break;
	case IKEv2_SET_WINDOW_SIZE:
		if (data->Size != 4) {
			Debug("Invalid syntax: NOTIFY_PAYLOAD - SET_WINDOW_SIZE\n");
			return IKEv2_INVALID_SYNTAX;
		}
		WriteBufInt(p->message, ReadBufInt(data));
		break;
	case IKEv2_NAT_DETECTION_DESTINATION_IP:
	case IKEv2_NAT_DETECTION_SOURCE_IP:
	default:
		p->message = data;
	}
	return IKEv2_NO_ERROR;
}

void ikev2_free_notify_payload(IKEv2_NOTIFY_PAYLOAD *p) {
	if (p == NULL) {
		return;
	}

	FreeBuf(p->message);
	FreeBuf(p->spi);
	Free(p);
}
/*            END NOTIFY PAYLOAD                      */

/*               DELETE PAYLOAD                       */
BUF* ikev2_delete_encode(IKEv2_DELETE_PAYLOAD* p) {
	assert(p);

	BUF *b = NewBuf();
	WriteBufChar(b, p->protocol_id);
	WriteBufChar(b, p->spi_size);
	WriteBufShort(b, p->num_spi);

	for (int i = 0; i < p->num_spi; i++) {
		BUF *spi = LIST_DATA(p->spi_list, i);
		WriteBuf(b, spi->Buf, spi->Size);
	}
	return b;
}

UINT ikev2_delete_decode(BUF *b, IKEv2_DELETE_PAYLOAD *p) {
	assert(b && p);

	if (b->Size < sizeof(UCHAR) * 2 + sizeof(USHORT)) {
		return IKEv2_INVALID_SYNTAX;
	}

	p->protocol_id = ReadBufChar(b);
	p->spi_size = ReadBufChar(b);
	p->num_spi = ReadBufShort(b);

	if (b->Size < p->spi_size * p->num_spi) {
		return IKEv2_INVALID_SYNTAX;
	}

	bool ok = true;
	p->spi_list = NewListFast(NULL);
	for (unsigned int i = 0; i < p->num_spi; i++) {
		BUF* spi = ReadBufFromBuf(b, p->spi_size);
		if (spi == NULL) {
			ok = false;
			break;
		}

		Add(p->spi_list, spi);
	}

	if (!ok) {
		ikev2_free_delete_payload(p);
		return IKEv2_INVALID_IKE_SPI;
	}
	return IKEv2_NO_ERROR;
}

void ikev2_free_delete_payload(IKEv2_DELETE_PAYLOAD* p) {
	if (p == NULL) {
		return;
	}

	if (p->spi_list != NULL) {
		for (UINT i = 0; i < LIST_NUM(p->spi_list); ++i) {
			BUF *spi = LIST_DATA(p->spi_list, i);
			FreeBuf(spi);
		}

		ReleaseList(p->spi_list);
		p->spi_list = NULL;
	}

	Free(p);
}
/*             END DELETE PAYLOAD                     */

/*                   VENDOR PAYLOAD                   */
BUF* ikev2_vendor_encode(IKEv2_VENDOR_PAYLOAD *p) {
	assert(p);

	BUF *b = NewBuf();
	WriteBufBuf(b, p->VID);

	return b;
}

UINT ikev2_vendor_decode(BUF *b, IKEv2_VENDOR_PAYLOAD *p) {
	p->VID = CloneBuf(b);
	return IKEv2_NO_ERROR;
}

void ikev2_free_vendor_payload(IKEv2_VENDOR_PAYLOAD *p) {
	if (p == NULL) {
		return;
	}

	FreeBuf(p->VID);
	Free(p);
}
/*                  END VENDOR PAYLOAD                 */

/*                   TS PAYLOAD                       */
BUF* ikev2_TS_encode(IKEv2_TS_PAYLOAD *p) {
	assert(p);

	BUF *b = NewBuf();
	WriteBufChar(b, p->TS_count);
	//reserved 3 bytes
	WriteBufShort(b, 0);
	WriteBufChar(b, 0);

	for (UINT i = 0; i < p->TS_count; ++i) {
		IKEv2_TRAFFIC_SELECTOR* selector = (IKEv2_TRAFFIC_SELECTOR*)LIST_DATA(p->selectors, i);

		WriteBufChar(b, selector->type);
		WriteBufChar(b, selector->IP_protocol_ID);
		WriteBufShort(b, selector->selector_length);
		WriteBufShort(b, selector->start_port);
		WriteBufShort(b, selector->end_port);
		if (selector->start_address->Size > 0) {
			WriteBufBuf(b, selector->start_address);
		}
		if (selector->end_address->Size > 0) {
			WriteBufBuf(b, selector->end_address);
		}
	}

	return b;
}

UINT ikev2_TS_decode(BUF *b, IKEv2_TS_PAYLOAD *p) {
	p->TS_count = ReadBufChar(b);
	//skip 3 bytes
	ReadBufShort(b);
	ReadBufChar(b);

	p->selectors = NewList(NULL);
	for (UINT i = 0; i < p->TS_count; ++i) {
		IKEv2_TRAFFIC_SELECTOR* selector = (IKEv2_TRAFFIC_SELECTOR*)Malloc(sizeof(IKEv2_TRAFFIC_SELECTOR));
		if (selector == NULL) {
			ikev2_free_TS_payload(p);
			Debug("error %d while allocating memory for TRAFFIC_SELECTOR", IKEv2_OUT_OF_MEMORY);
			return IKEv2_OUT_OF_MEMORY;
		}

		selector->type = ReadBufChar(b);
		selector->IP_protocol_ID = ReadBufChar(b);
		selector->selector_length = ReadBufShort(b);
		selector->start_port = ReadBufShort(b);
		selector->end_port = ReadBufShort(b);

		UINT addr_size = 0;
		switch (selector->type)
		{
		case IKEv2_TS_IPV4_ADDR_RANGE:
			addr_size = 4;
			break;
		case IKEv2_TS_IPV6_ADDR_RANGE:
			addr_size = 16;
			break;
		default:
			Dbg("Unknown type in Traffic Selector: %d, skipping\n", selector->type);
			break;
		}

		if (addr_size == 0) {
			Free(selector);
		}
		else {
			selector->start_address = ReadBufFromBuf(b, addr_size);
			selector->end_address = ReadBufFromBuf(b, addr_size);

			Add(p->selectors, (void*)selector);
		}
	}

	return IKEv2_NO_ERROR;
}

void ikev2_free_TS_payload(IKEv2_TS_PAYLOAD *p) {
	if (p == NULL) {
		return;
	}

	for (UINT i = 0; i < p->TS_count; ++i) {
		IKEv2_TRAFFIC_SELECTOR* selector = (IKEv2_TRAFFIC_SELECTOR*)LIST_DATA(p->selectors, i);

		FreeBuf(selector->start_address);
		FreeBuf(selector->end_address);
		Free(selector);
		selector = NULL;
	}
	ReleaseList(p->selectors);

	Free(p);
}
/*                  END TS PAYLOAD                    */

/*                   SK PAYLOAD                       */
BUF* ikev2_SK_encode(IKEv2_SK_PAYLOAD *p) {
	BUF *b = NewBuf();
	WriteBufBuf(b, p->init_vector);
	WriteBufBuf(b, p->encrypted_payloads); // encrypted info with padding and pad_length is contained in encrypted payloads
	WriteBufBuf(b, p->integrity_checksum); // should be calculated over payload when it's already encrypted

	return b;
}

UINT ikev2_SK_decode(BUF *b, IKEv2_SK_PAYLOAD *p) {
    if (b->Buf == NULL) {
		return IKEv2_INVALID_SYNTAX;
	}

	Dbg("sk decoding, len: %u", b->Size);
	p->raw_data = CloneBuf(b);
	p->decrypted_payloads = NewList(NULL);
	p->encrypted_payloads = NULL;
	p->init_vector = NULL;
	p->integrity_checksum = NULL;
	p->padding = NULL;
	p->pad_length = 0;
	Dbg("sk decoded");
	return IKEv2_NO_ERROR;
}

void ikev2_free_SK_payload(IKEv2_SK_PAYLOAD *p) {
	if (p == NULL) {
		return;
	}

	FreeBuf(p->raw_data);
	FreeBuf(p->init_vector);
	FreeBuf(p->encrypted_payloads);
	FreeBuf(p->padding);
	FreeBuf(p->integrity_checksum);

	Free(p);
}
/*                  END SK PAYLOAD                    */

/*          CONFIGURATION PAYLOAD                     */
BUF* ikev2_configuration_encode(IKEv2_CP_PAYLOAD *p) {
	if (p == NULL) {
		return NULL;
	}

	BUF* b = NewBuf();
	WriteBufChar(b, p->type);
	WriteBufChar(b, 0);
	WriteBufShort(b, (USHORT)0);

	UINT attrCount = LIST_NUM(p->attributes);
	for (UINT i = 0; i < attrCount; ++i) {
		IKEv2_CP_ATTR* a = (IKEv2_CP_ATTR*)LIST_DATA(p->attributes, i);

		BUF *tmp = NewBuf();
		
		WriteBufShort(tmp, a->type);
		WriteBufShort(tmp, a->length);

		if (a->value != NULL) {
			WriteBufBuf(tmp, a->value);
		}
		
		WriteBufBuf(b, tmp);
		FreeBuf(tmp);
	}

	return b;
}

UINT ikev2_configuration_decode(BUF *b, IKEv2_CP_PAYLOAD *p) {
	p->type = ReadBufChar(b);
	ReadBufChar(b);
	ReadBufShort(b);

	p->attributes = NewList(NULL);

	UINT remains = ReadBufRemainSize(b);
	if (remains < 4) {
		return IKEv2_INVALID_SYNTAX;
	}

	for (UINT i = 0; i < remains;) {
		IKEv2_CP_ATTR* attr = (IKEv2_CP_ATTR*)ZeroMalloc(sizeof(IKEv2_CP_ATTR));

		attr->type = ReadBufShort(b) & ((1 << 15) - 1);
		Dbg("CP payload: got attribute of type %u", attr->type);
		/* if (attr->type < 1 || attr->type > 15) { */
		/* return IKEv2_INVALID_SYNTAX; */
		/* } */

		attr->length = ReadBufShort(b);
		i += 4;
		if (attr->length > 0) {
			attr->value = ReadBufFromBuf(b, attr->length);

			i += attr->length;
		}

		if (i > remains) {
			return IKEv2_INVALID_SYNTAX;
		}

		Add(p->attributes, attr);
	}

	return IKEv2_NO_ERROR;
}

void ikev2_free_configuration_payload(IKEv2_CP_PAYLOAD *p) {
	if (p == NULL) {
		return;
	}

	for (UINT i = 0; i < LIST_NUM(p->attributes); ++i) {
		IKEv2_CP_ATTR* attr = LIST_DATA(p->attributes, i);
		if (attr->value != NULL) {
			FreeBuf(attr->value);
		}
		Free(attr);
		attr = NULL;
	}

	ReleaseList(p->attributes);

	Free(p);
}
/*        END CONFIGURATION PAYLOAD                   */

/*                    EAP PAYLOAD                     */
BUF* ikev2_EAP_encode(IKEv2_EAP_PAYLOAD *p) {
	if (p == NULL) {
		return NULL;
	}

	BUF *b = NewBuf();
	WriteBufChar(b, p->code);
	WriteBufChar(b, p->identifier);
	WriteBufShort(b, p->length);
	if (p->code == 1 || p->code == 2) {
		WriteBufChar(b, p->type);
		WriteBufBuf(b, p->type_data);
	}

	return b;
}

UINT ikev2_EAP_decode(BUF *b, IKEv2_EAP_PAYLOAD *p) {
	if (b == NULL || p == NULL) {
		return 1;
	}

	p->code = ReadBufChar(b);
	p->identifier = ReadBufChar(b);
	p->length = ReadBufShort(b);

	if (p->code == 1 || p->code == 2) {
		p->type = ReadBufChar(b);
		p->type_data = ReadRemainBuf(b);
	}

	return IKEv2_NO_ERROR;
}

void ikev2_free_EAP_payload(IKEv2_EAP_PAYLOAD *p) {
	if (p == NULL) {
		return;
	}

	if (p->type_data != NULL) {
		FreeBuf(p->type_data);
	}

	Free(p);
}
/*                  END EAP PAYLOAD                    */

/* Helper functions section. */
IKEv2_SA_TRANSFORM* Ikev2CloneTransform(IKEv2_SA_TRANSFORM* other) {
	if (other == NULL) {
		return NULL;
	}

	IKEv2_SA_TRANSFORM* clone = (IKEv2_SA_TRANSFORM*)Malloc(sizeof(IKEv2_SA_TRANSFORM));
	if (clone == NULL) {
		Dbg("error while allocating memory");
		return NULL;
	}

	clone->is_last = other->is_last;
	clone->transform_length = other->transform_length;
	clone->transform.ID = other->transform.ID;
	clone->transform.type = other->transform.type;

	if (other->attributes != NULL) {
		clone->attributes = NewList(NULL);
		UINT attr_count = LIST_NUM(other->attributes);

		for (UINT i = 0; i < attr_count; ++i) {
			IKEv2_TRANSFORM_ATTRIBUTE* attr = (IKEv2_TRANSFORM_ATTRIBUTE*)Malloc(sizeof(IKEv2_TRANSFORM_ATTRIBUTE));
			if (clone == NULL) {
				ikev2_free_SA_transform(clone);
				Dbg("error while allocating memory");
				return NULL;
			}
			IKEv2_TRANSFORM_ATTRIBUTE* oa = (IKEv2_TRANSFORM_ATTRIBUTE*)LIST_DATA(other->attributes, i);

			attr->format = oa->format;
			attr->type = oa->type;
			attr->value = oa->value;
			attr->TLV_value = NULL;
			if (oa->TLV_value != NULL) {
				attr->TLV_value = CloneBuf(oa->TLV_value);
			}

			Add(clone->attributes, (void*)attr);
		}
	}

	return clone;
}

// Returns 0 if error not present
USHORT Ikev2GetNotificationErrorCode(USHORT notification_type) {
  switch (notification_type) {
  case IKEv2_UNSUPPORTED_CRITICAL_PAYLOAD:
  case IKEv2_INVALID_IKE_SPI:
  case IKEv2_INVALID_MAJOR_VERSION:
  case IKEv2_INVALID_SYNTAX:
  case IKEv2_INVALID_MESSAGE_ID:
  case IKEv2_INVALID_SPI:
  case IKEv2_NO_PROPOSAL_CHOSEN:
  case IKEv2_INVALID_KE_PAYLOAD:
  case IKEv2_AUTHENTICATION_FAILED:
  case IKEv2_SINGLE_PAIR_REQUIRED:
  case IKEv2_NO_ADDITIONAL_SAS:
  case IKEv2_INTERNAL_ADDRESS_FAILURE:
  case IKEv2_FAILED_CP_REQUIRED:
  case IKEv2_TS_UNACCEPTABLE:
  case IKEv2_INVALID_SELECTORS:
  case IKEv2_TEMPORARY_FAILURE:
  case IKEv2_CHILD_SA_NOT_FOUND:
    return notification_type;
  default:
    return IKEv2_NO_ERROR;
  }
}

BUF* EndianBuf(BUF* b) {
	if (b == NULL) {
		return NULL;
	}
	
	if (b->Size == 1) {
		return CloneBuf(b);
	}

	BUF *bb = NewBuf();
	for (UINT i = b->Size; i > 0; i--) {
		WriteBufChar(bb, *((UCHAR*)(b->Buf) + i - 1));
	}

	return bb;
}

void Endian(UCHAR* b, UCHAR* bb, UINT size) {
  if (b == NULL) {
    return;
  }

  UINT k = 0;
  for (UINT i = size; i > 0; i--) {
    *(bb+k) = *(b + i - 1);
    k++;
  }
}

void DbgPointer(char* text, void* p, UINT size) {
  Debug("Pointer %s:", text);
  UINT si = 0;
  for (UINT i = 0; i < size; ++i) {
    if (i % 16 == 0) {
      Debug("\n\t%4u: ", si);
      si+=16;
    }
    Debug("%02X ", *((UCHAR*)p + i));
  }
  Debug("\n");
}
