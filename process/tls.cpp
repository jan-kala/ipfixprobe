/**
 * \file tls.cpp
 * \brief Plugin for parsing https traffic.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \author Ondrej Sedlacek <xsedla1o@stud.fit.vutbr.cz>
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
 * \date 2018-2020
 */

/*
 * Copyright (C) 2018 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#include <iostream>
#include <sstream>

#include <stdio.h>

#include "tls.hpp"
#include "md5.hpp"

namespace ipxp {

int RecordExtTLS::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("tls", [](){return new TLSPlugin();});
   register_plugin(&rec);
   RecordExtTLS::REGISTERED_ID = register_extension();
}

//#define DEBUG_TLS

// Print debug message if debugging is allowed.
#ifdef DEBUG_TLS
# define DEBUG_MSG(format, ...) fprintf(stderr, format, ## __VA_ARGS__)
#else
# define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_TLS
# define DEBUG_CODE(code) code
#else
# define DEBUG_CODE(code)
#endif

TLSPlugin::TLSPlugin() : ext_ptr(nullptr), parsed_sni(0), flow_flush(false)
{
}

TLSPlugin::~TLSPlugin()
{
   close();
}

void TLSPlugin::init(const char *params)
{
}

void TLSPlugin::close()
{
   if (ext_ptr != nullptr) {
      delete ext_ptr;
      ext_ptr = nullptr;
   }
}

ProcessPlugin *TLSPlugin::copy()
{
   return new TLSPlugin(*this);
}

int TLSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   add_tls_record(rec, pkt);
   return 0;
}

int TLSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtTLS *ext = static_cast<RecordExtTLS *>(rec.get_extension(RecordExtTLS::REGISTERED_ID));

   if (ext != nullptr) {
      if (ext->alpn[0] == 0) {
         // Add ALPN from server packet
         parse_tls((const char *) pkt.payload, pkt.payload_len, ext);
      }
      return 0;
   }
   add_tls_record(rec, pkt);

   return 0;
}

/*
 * Checking for reserved GRESE values.
 * The list of reserved values: https://tools.ietf.org/html/draft-ietf-tls-grease-01
 */
bool is_grease_value(uint16_t val)
{
   if (val != 0 && !(val & ~(0xFAFA)) && ((0x00FF & val) == (val >> 8))) {
      return true;
   }
   return false;
}

void get_ja3_cipher_suites(std::string &ja3, payload_data &data)
{
   int cipher_suites_length = ntohs(*(uint16_t *) data.data);
   uint16_t type_id         = 0;
   const char *section_end  = data.data + cipher_suites_length;

   if (data.data + cipher_suites_length + 1 > data.end) {
      data.valid = false;
      return;
   }
   data.data += 2;

   for (; data.data <= section_end; data.data += sizeof(uint16_t)) {
      type_id = ntohs(*(uint16_t *) (data.data));
      if (!is_grease_value(type_id)) {
         ja3 += std::to_string(type_id);
         if (data.data < section_end) {
            ja3 += '-';
         }
      }
   }
   ja3 += ',';
}

bool parse_tls_nonext_hdr(payload_data &payload, std::string *ja3)
{
   tls_handshake *tls_hs = (tls_handshake *) payload.data;
   const uint8_t hs_type = tls_hs->type;
   if (payload.data + sizeof(tls_handshake) > payload.end ||
      !(hs_type == TLS_HANDSHAKE_CLIENT_HELLO || hs_type == TLS_HANDSHAKE_SERVER_HELLO)) {
      return false;
   }

   //uint32_t hs_len = tls_hs->length1 << 16 | ntohs(tls_hs->length2);

   // 1 + 3 + 2 + 32 + 1 + 2 + 1 + 2 = 44
   // type + length + version + random + sessionid + ciphers + compression + ext-len
   if (payload.data + 44 > payload.end || tls_hs->version.major != 3 ||
     tls_hs->version.minor < 1 || tls_hs->version.minor > 3) {
      return false;
   }
   payload.data += sizeof(tls_handshake);

   if (ja3) {
      *ja3 += std::to_string((uint16_t) tls_hs->version.version) + ',';
   }

   payload.data += 32; // Skip random

   int tmp = *(uint8_t *) payload.data;
   if (payload.data + tmp + 2 > payload.end) {
      return false;
   }
   payload.data += tmp + 1; // Skip session id

   if (hs_type == TLS_HANDSHAKE_CLIENT_HELLO) {
      if (ja3) {
         get_ja3_cipher_suites(*ja3, payload);
         if (!payload.valid) {
            return false;
         }
      } else {
         if (payload.data + 2 > payload.end) {
            return false;
         }
         payload.data += ntohs(*(uint16_t *) payload.data) + 2; // Skip cipher suites
      }

      tmp = *(uint8_t *) payload.data;
      if (payload.data + tmp + 3 > payload.end) { // check space for (1+tmp) bytes of compression + next 2 bytes of exts length
         return false;
      }
      payload.data += tmp + 1; // Skip compression methods
   } else {
      /* TLS_HANDSHAKE_SERVER_HELLO */
      payload.data += 2; // Skip cipher suite
      payload.data += 1; // Skip compression method
   }

   const char *ext_end = payload.data + ntohs(*(uint16_t *) payload.data) + 2;
   payload.data += 2;
   if (ext_end <= payload.end) {
      payload.end = ext_end;
   }

   return true;
}

bool TLSPlugin::parse_tls(const char *data, uint16_t payload_len, RecordExtTLS *rec)
{
   payload_data payload = {
      (char *) data,
      data + payload_len,
      true,
      0
   };

   std::string ecliptic_curves;
   std::string ec_point_formats;
   std::string ja3;

   tls_rec *tls = (tls_rec *) payload.data;
   if (payload.data + sizeof(tls_rec) > payload.end || !tls || tls->type != TLS_HANDSHAKE ||
     tls->version.major != 3 || tls->version.minor > 3) {
      return false;
   }
   payload.data += sizeof(tls_rec);

   tls_handshake *tls_hs = (tls_handshake *) payload.data;
   const uint8_t hs_type = tls_hs->type;

   if (!parse_tls_nonext_hdr(payload, &ja3)) {
      return false;
   }
   rec->version = ((uint16_t) tls_hs->version.major << 8) | tls_hs->version.minor;

   while (payload.data + sizeof(tls_ext) <= payload.end) {
      tls_ext *ext    = (tls_ext *) payload.data;
      uint16_t length = ntohs(ext->length);
      uint16_t type   = ntohs(ext->type);

      payload.data += sizeof(tls_ext);
      if (payload.data + length > payload.end) {
         break;
      }

      if (hs_type == TLS_HANDSHAKE_CLIENT_HELLO) {
         if (type == TLS_EXT_SERVER_NAME) {
            get_tls_server_name(payload, rec->sni, sizeof(rec->sni));
            parsed_sni += payload.sni_parsed;
         } else if (type == TLS_EXT_ECLIPTIC_CURVES) {
            ecliptic_curves = get_ja3_ecpliptic_curves(payload);
         } else if (type == TLS_EXT_EC_POINT_FORMATS) {
            ec_point_formats = get_ja3_ec_point_formats(payload);
         }
      } else { /* TLS_HANDSHAKE_SERVER_HELLO */
         if (type == TLS_EXT_ALPN) {
            get_alpn(payload, rec);
            return true;
         }
      }

      if (!payload.valid) {
         if (hs_type == TLS_HANDSHAKE_CLIENT_HELLO) {
            rec->sni[0] = 0;
         }
         return false;
      }
      payload.data += length;
      if (!is_grease_value(type)) {
         ja3 += std::to_string(type);

         if (payload.data + sizeof(tls_ext) <= payload.end) {
            ja3 += '-';
         }
      }
   }
   if (hs_type == TLS_HANDSHAKE_SERVER_HELLO) {
      return false;
   }

   ja3 += ',' + ecliptic_curves + ',' + ec_point_formats;
   md5_get_bin(ja3, rec->ja3_hash_bin);

   DEBUG_CODE(for(int i = 0; i < 16; i++){
       DEBUG_MSG("%02x", rec->ja3_hash_bin[i]);
   })
   DEBUG_MSG("\n");
   DEBUG_MSG("%s\n", ja3.c_str());

   return payload.sni_parsed != 0 || !ja3.empty();
} // TLSPlugin::parse_sni

void get_tls_server_name(payload_data &data, char *out, size_t bufsize)
{
   uint16_t list_len    = ntohs(*(uint16_t *) data.data);
   uint16_t offset      = sizeof(list_len);
   const char *list_end = data.data + list_len + offset;

   if (list_end > data.end) {
      data.valid = false;
      return;
   }

   while (data.data + sizeof(tls_ext_sni) + offset < list_end) {
      tls_ext_sni *sni = (tls_ext_sni *) (data.data + offset);
      uint16_t sni_len = ntohs(sni->length);

      offset += sizeof(tls_ext_sni);
      if (data.data + offset + sni_len > list_end) {
         break;
      }
      if (out[0] != 0) {
         break;
      }
      if (sni_len + (size_t) 1 > bufsize) {
         sni_len = bufsize - 1;
      }
      memcpy(out, data.data + offset, sni_len);
      out[sni_len] = 0;
      data.sni_parsed++;
      offset += ntohs(sni->length);
   }
}

void TLSPlugin::get_alpn(payload_data &data, RecordExtTLS *rec)
{
   uint16_t list_len    = ntohs(*(uint16_t *) data.data);
   uint16_t offset      = sizeof(list_len);
   const char *list_end = data.data + list_len + offset;

   if (list_end > data.end) {
      data.valid = false;
      return;
   }
   if (rec->alpn[0] != 0) {
      return;
   }

   uint16_t alpn_written = 0;
   while (data.data + sizeof(uint8_t) + offset < list_end) {
      uint8_t alpn_len = *(uint8_t *) (data.data + offset);
      const char *alpn_str = data.data + offset + sizeof(uint8_t);

      offset += sizeof(uint8_t) + alpn_len;
      if (data.data + offset > list_end) {
         break;
      }
      if (alpn_written + alpn_len + (size_t) 2 >= sizeof(rec->alpn)) {
         break;
      }

      if (alpn_written != 0) {
         rec->alpn[alpn_written++] = ';';
      }
      memcpy(rec->alpn + alpn_written, alpn_str, alpn_len);
      alpn_written += alpn_len;
      rec->alpn[alpn_written] = 0;
   }
}

std::string TLSPlugin::get_ja3_ecpliptic_curves(payload_data &data)
{
   std::string collected_types;
   uint16_t type_id     = 0;
   uint16_t list_len    = ntohs(*(uint16_t *) data.data);
   const char *list_end = data.data + list_len + sizeof(list_len);
   uint16_t offset      = sizeof(list_len);

   if (list_end > data.end) {
      data.valid = false;
      return "";
   }

   while (data.data + sizeof(uint16_t) + offset <= list_end) {
      type_id = ntohs(*(uint16_t *) (data.data + offset));
      offset += sizeof(uint16_t);
      if (!is_grease_value(type_id)) {
         collected_types += std::to_string(type_id);

         if (data.data + sizeof(uint16_t) + offset <= list_end) {
            collected_types += '-';
         }
      }
   }
   return collected_types;
}

std::string TLSPlugin::get_ja3_ec_point_formats(payload_data &data)
{
   std::string collected_formats;
   uint8_t list_len     = *data.data;
   uint16_t offset      = sizeof(list_len);
   const char *list_end = data.data + list_len + offset;
   uint8_t format;

   if (list_end > data.end) {
      data.valid = false;
      return "";
   }

   while (data.data + sizeof(uint8_t) + offset <= list_end) {
      format = *(data.data + offset);
      collected_formats += std::to_string((int)format);
      offset += sizeof(uint8_t);
      if (data.data + sizeof(uint8_t) + offset <= list_end) {
         collected_formats += '-';
      }
   }
   return collected_formats;
}

void TLSPlugin::add_tls_record(Flow &rec, const Packet &pkt)
{
   if (ext_ptr == nullptr) {
      ext_ptr = new RecordExtTLS();
   }

   if (parse_tls(reinterpret_cast<const char *>(pkt.payload), pkt.payload_len, ext_ptr)) {
      rec.add_extension(ext_ptr);
      ext_ptr = nullptr;
   }
}

void TLSPlugin::finish(bool print_stats)
{
   if (print_stats) {
      std::cout << "TLS plugin stats:" << std::endl;
      std::cout << "   Parsed SNI: " << parsed_sni << std::endl;
   }
}

}
