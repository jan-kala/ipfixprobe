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
#include "utils.hpp"

namespace ipxp {

int RecordExtRTP::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("rtp", [](){return new RTPPlugin();});
   register_plugin(&rec);
   RecordExtRTP::REGISTERED_ID = register_extension();
}

RTPPlugin::RTPPlugin() : total(0), total_rtp(0)
{
}

RTPPlugin::~RTPPlugin()
{
}

void RTPPlugin::init(const char *params)
{
}

void RTPPlugin::close()
{
}

ProcessPlugin *RTPPlugin::copy()
{
   return new RTPPlugin(*this);
}

int RTPPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int RTPPlugin::post_create(Flow &rec, const Packet &pkt)
{

   if(!validate_rtp(pkt))
      return 0;

   total++;
   total_rtp++;

   RecordExtRTP * rtp_record = new RecordExtRTP();
   rec.add_extension(rtp_record);
   manage_packet(rec, pkt);

   return 0;
}

int RTPPlugin::pre_update(Flow &rec, Packet &pkt)
{
   manage_packet(rec,pkt);
   return 0;
}

int RTPPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void RTPPlugin::pre_export(Flow &rec)
{
}

bool RTPPlugin::validate_rtp(const Packet &pkt){

   if(pkt.ip_proto != IPPROTO_UDP)
      return false;

   if(pkt.payload_len < RTP_HEADER_MINIMUM_SIZE)
      return false;

   if(pkt.dst_port < 1024)
      return false;

   return true;

}

void RTPPlugin::manage_packet(const Flow & rec, const Packet &pkt){

   RecordExtRTP * rtp_record = static_cast<RecordExtRTP *>(rec.get_extension(RecordExtRTP::REGISTERED_ID));

   if(!rtp_record ||
      !rtp_record->is_rtp ||
      rec.dst_packets > RTP_ANALYSIS_PACKETS ||
      rec.src_packets > RTP_ANALYSIS_PACKETS)
      return;

   if(!validate_rtp(pkt)){
      rtp_record->is_rtp = false;
      total_rtp--;
      return;
   }

   struct rtp_header & rtp_header_flow = rtp_record->rtp_header_src;

   if(utils::ipaddr_compare(pkt.src_ip, rec.src_ip, pkt.ip_version) && 
      pkt.src_port == rec.src_port
      ){ // direction forward ->
      
      if(!(rtp_record->rtp_header_filled & RTP_HEADER_SRC_FILLED) ){
         fill_rtp_record(pkt,&rtp_record->rtp_header_src);
         rtp_record->rtp_header_filled |= RTP_HEADER_SRC_FILLED;
         return;
      }

      rtp_header_flow = rtp_record->rtp_header_src;

   }
   else { //direction back <-

      if(!(rtp_record->rtp_header_filled & RTP_HEADER_DST_FILLED)){
         fill_rtp_record(pkt,&rtp_record->rtp_header_dst);
         rtp_record->rtp_header_filled |= RTP_HEADER_DST_FILLED;
         return;
      }

      rtp_header_flow = rtp_record->rtp_header_dst;

   }

   if(!verify_rtp(pkt,rtp_header_flow)){
      rtp_record->is_rtp = false;
      total_rtp--;
      return;
   }

   struct rtp_header * rtp_header = (struct rtp_header *) pkt.payload;

   //refresh with new values
   rtp_header_flow.sequence_number = ntohs(rtp_header->sequence_number);
   rtp_header_flow.timestamp = ntohl(rtp_header->timestamp);

}

void RTPPlugin::fill_rtp_record(const Packet &pkt, struct rtp_header * rtp_header){

   memcpy(rtp_header, pkt.payload, sizeof(struct rtp_header));
   
   rtp_header->sequence_number = ntohs(rtp_header->sequence_number);
   rtp_header->timestamp = ntohl(rtp_header->timestamp);
   rtp_header->ssrc = ntohl(rtp_header->ssrc);

}

bool RTPPlugin::verify_rtp(const Packet &pkt, const struct rtp_header & rtp_header_flow){

   struct rtp_header * rtp_header = (struct rtp_header *) pkt.payload;

   uint16_t sequence_number = ntohs(rtp_header->sequence_number);
   uint32_t timestamp = ntohl(rtp_header->timestamp);
   uint32_t ssrc = ntohl(rtp_header->ssrc);

   bool is_rtp = 
      rtp_header_flow.ssrc == ssrc && 
      rtp_header_flow.sequence_number < sequence_number &&
      rtp_header_flow.timestamp < timestamp;

   return is_rtp;

}


}
