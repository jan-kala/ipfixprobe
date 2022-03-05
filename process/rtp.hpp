/**
 * \file rtp.hpp
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

#ifndef IPXP_PROCESS_RTP_HPP
#define IPXP_PROCESS_RTP_HPP

#include <cstring>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

#define RTP_UNIREC_TEMPLATE "" /* TODO: unirec template */

UR_FIELDS (
   /* TODO: unirec fields definition */
)

/**
 * \brief Flow record extension header for storing parsed RTP data.
 */
struct RecordExtRTP : public RecordExt {
   static int REGISTERED_ID;

   RecordExtRTP() : RecordExt(REGISTERED_ID)
   {
   }

#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
   }

   const char *get_unirec_tmplt() const
   {
      return RTP_UNIREC_TEMPLATE;
   }
#endif

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      return 0;
   }

   const char **get_ipfix_tmplt() const
   {
      return 0;
   }
};

/**
 * \brief Process plugin for parsing RTP packets.
 */
class RTPPlugin : public ProcessPlugin
{
public:
   RTPPlugin();
   ~RTPPlugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("rtp", "Parse RTP traffic"); }
   std::string get_name() const { return "rtp"; }
   RecordExt *get_ext() const { return new RecordExtRTP(); }
   ProcessPlugin *copy();

   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);
};

}
#endif /* IPXP_PROCESS_RTP_HPP */

