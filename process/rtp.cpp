/**
 * \file rtp.cpp
 * \brief Plugin for parsing rtp traffic.
 * \author STEPAN SIMEK simekst2@fit.cvut.cz
 * \date 2022
 */
/*
 * Copyright (C) 2022 CESNET
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

#include "rtp.hpp"
#include <ipfixprobe/utils.hpp>

namespace ipxp {
int RecordExtRTP::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("rtp", [](){
         return new RTPPlugin();
      });

   register_plugin(&rec);
   RecordExtRTP::REGISTERED_ID = register_extension();
}

RTPPlugin::RTPPlugin()
{ }

RTPPlugin::~RTPPlugin()
{ }

void RTPPlugin::init(const char *params)
{ }

void RTPPlugin::close()
{ }

ProcessPlugin *RTPPlugin::copy()
{
   return new RTPPlugin(*this);
}

int RTPPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtRTP *rtp_record = new RecordExtRTP();

   rec.add_extension(rtp_record);

   manage_packet(rec, pkt);

   return 0;
}

int RTPPlugin::pre_update(Flow &rec, Packet &pkt)
{
   manage_packet(rec, pkt);
   return 0;
}

void RTPPlugin::pre_export(Flow &rec)
{ }

bool RTPPlugin::validate_rtp(const Packet &pkt)
{
   if (pkt.ip_version != 0x04 || pkt.ip_proto != IPPROTO_UDP)
      return false;

   if (pkt.payload_len < RTP_HEADER_MINIMUM_SIZE)
      return false;

   if (pkt.dst_port == 53 || pkt.src_port == 53)
      return false;

   struct rtp_header *rtp_header = (struct rtp_header *) pkt.payload;

   if (rtp_header->version != 2)
      return false;

   if (rtp_header->payload_type >= 72 && rtp_header->payload_type <= 95)
      return false;

   return true;
}

void RTPPlugin::manage_packet(const Flow & rec, const Packet &pkt)
{
   RecordExtRTP *rtp_record = static_cast<RecordExtRTP *>(rec.get_extension(RecordExtRTP::REGISTERED_ID));

   uint8_t direction = FLOW_PACKET_DIRECTION_SAME;

   if (ipaddr_compare(pkt.src_ip, rec.src_ip, pkt.ip_version) &&
     pkt.src_port == rec.src_port
   ) {
      direction = FLOW_PACKET_DIRECTION_SAME;
   } else {
      direction = FLOW_PACKET_DIRECTION_DIFFERENT;
   }

   if (direction == FLOW_PACKET_DIRECTION_SAME) {
      if (rtp_record->rtp_header_filled & RTP_HEADER_SRC_EMPTY) {
         if (!validate_rtp(pkt))
            return;

         fill_rtp_record(pkt, rtp_record->rtp_header_src);

         rtp_record->rtp_header_filled ^= RTP_HEADER_SRC_EMPTY;
         rtp_record->rtp_header_filled |= RTP_HEADER_SRC_MATCHING;
      } else if (rtp_record->rtp_header_filled & RTP_HEADER_SRC_MATCHING) {
         if (!validate_rtp(pkt))
            return;

         if (verify_rtp(pkt, rtp_record->rtp_header_src)) {
            update_rtp_record(pkt, rtp_record->rtp_header_src);

            rtp_record->rtp_counter.total_src_after_recognition++;
            rtp_record->rtp_counter.rtp_src++;

            rtp_record->rtp_header_filled ^= RTP_HEADER_SRC_MATCHING;
            rtp_record->rtp_header_filled |= RTP_HEADER_SRC_INITIALIZED;
         } else {
            fill_rtp_record(pkt, rtp_record->rtp_header_src);
         }
      } else if (rtp_record->rtp_header_filled & RTP_HEADER_SRC_INITIALIZED) {
         if (validate_rtp(pkt) && verify_rtp(pkt, rtp_record->rtp_header_src)) {
            update_rtp_record(pkt, rtp_record->rtp_header_src);

            rtp_record->rtp_counter.rtp_src++;
         }
         rtp_record->rtp_counter.total_src_after_recognition++;
      }
   } else {
      if (rtp_record->rtp_header_filled & RTP_HEADER_DST_EMPTY) {
         if (!validate_rtp(pkt))
            return;

         fill_rtp_record(pkt, rtp_record->rtp_header_dst);

         rtp_record->rtp_header_filled ^= RTP_HEADER_DST_EMPTY;
         rtp_record->rtp_header_filled |= RTP_HEADER_DST_MATCHING;
      } else if (rtp_record->rtp_header_filled & RTP_HEADER_DST_MATCHING) {
         if (!validate_rtp(pkt))
            return;

         if (verify_rtp(pkt, rtp_record->rtp_header_dst)) {
            update_rtp_record(pkt, rtp_record->rtp_header_dst);

            rtp_record->rtp_counter.total_dst_after_recognition++;
            rtp_record->rtp_counter.rtp_dst++;

            rtp_record->rtp_header_filled ^= RTP_HEADER_DST_MATCHING;
            rtp_record->rtp_header_filled |= RTP_HEADER_DST_INITIALIZED;
         } else {
            fill_rtp_record(pkt, rtp_record->rtp_header_dst);
         }
      } else if (rtp_record->rtp_header_filled & RTP_HEADER_DST_INITIALIZED) {
         if (validate_rtp(pkt) && verify_rtp(pkt, rtp_record->rtp_header_dst)) {
            update_rtp_record(pkt, rtp_record->rtp_header_dst);

            rtp_record->rtp_counter.rtp_dst++;
         }

         rtp_record->rtp_counter.total_dst_after_recognition++;
      }
   }
} // RTPPlugin::manage_packet

void RTPPlugin::fill_rtp_record(const Packet &pkt, struct rtp_header &rtp_header)
{
   memcpy(&rtp_header, pkt.payload, sizeof(struct rtp_header));

   convert_rtp_record(rtp_header);
}

void RTPPlugin::update_rtp_record(const Packet &pkt, struct rtp_header &rtp_header_record)
{
   struct rtp_header *rtp_header_packet = (struct rtp_header *) pkt.payload;

   rtp_header_record.sequence_number = rtp_header_packet->sequence_number;
   rtp_header_record.timestamp       = rtp_header_packet->timestamp;
   rtp_header_record.ssrc         = rtp_header_packet->ssrc;
   rtp_header_record.payload_type = rtp_header_packet->payload_type;

   convert_rtp_record(rtp_header_record);
}

void RTPPlugin::convert_rtp_record(struct rtp_header &rtp_header)
{
   rtp_header.sequence_number = ntohs(rtp_header.sequence_number);
   rtp_header.timestamp       = ntohl(rtp_header.timestamp);
   rtp_header.ssrc = ntohl(rtp_header.ssrc);
}

bool RTPPlugin::verify_rtp(const Packet &pkt, const struct rtp_header &rtp_header_record)
{
   struct rtp_header *rtp_header = (struct rtp_header *) pkt.payload;

   uint16_t sequence_number = ntohs(rtp_header->sequence_number);
   uint32_t timestamp       = ntohl(rtp_header->timestamp);
   uint32_t ssrc = ntohl(rtp_header->ssrc);

   uint16_t payload_type = rtp_header->payload_type;

   bool is_rtp = false;

   if (payload_type == rtp_header_record.payload_type) {
      is_rtp =
        rtp_header_record.ssrc == ssrc &&
        (std::abs(sequence_number - rtp_header_record.sequence_number) < RTP_SEQUENCE_NUMBER_MAX_DIFFERENCE ) &&
        (std::abs((int64_t) timestamp - rtp_header_record.timestamp) < RTP_TIMESTAMP_MAX_DIFFERENCE );
   } else {
      is_rtp =
        rtp_header_record.ssrc == ssrc;
   }

   return is_rtp;
}
}
