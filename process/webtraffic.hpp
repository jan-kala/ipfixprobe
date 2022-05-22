/**
 * \file webtraffic.hpp
 * \brief Plugin for parsing webtraffic traffic.
 * \author Jan Kala <xkalaj01@stud.fit.vutbr.cz>
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

#ifndef IPXP_PROCESS_WEBTRAFFIC_HPP
#define IPXP_PROCESS_WEBTRAFFIC_HPP

#include <string>
#include <sstream>
#include <cstring>
#include <nlohmann/json.hpp>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

#define DEFAULT_FILL_TEXT "UNDEFINED"

#define WEBTRAFFIC_UNIREC_TEMPLATE \
   "WEBTRAFFIC_HOSTNAME" /* TODO: unirec template */

UR_FIELDS (
   /* TODO: unirec fields definition */
   string WEBTRAFFIC_HOSTNAME,
)

namespace ipxp {

using namespace nlohmann;

/**
 * \brief Flow record extension header for storing parsed WEBTRAFFIC data.
 */
struct RecordExtWEBTRAFFIC : public RecordExt {
   static int REGISTERED_ID;
   std::string    hostname;

   RecordExtWEBTRAFFIC() : RecordExt(REGISTERED_ID)
   {
      hostname = DEFAULT_FILL_TEXT;
   }

   RecordExtWEBTRAFFIC(const RecordExtWEBTRAFFIC *record) : RecordExt(REGISTERED_ID)
   {
      hostname = record->hostname;
   }
   
#ifdef WITH_NEMEA
   virtual void fill_unirec(ur_template_t *tmplt, void *record)
   {
   }

   const char *get_unirec_tmplt() const
   {
      return WEBTRAFFIC_UNIREC_TEMPLATE;
   }
#endif // ifdef WITH_NEMEA

   virtual int fill_ipfix(uint8_t *buffer, int size)
   {
      int length, total_length = 0;

      // WEBTRAFFIC_HOSTNAME
      length = hostname.length();
      if (total_length + length + 1 > size){
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, hostname.c_str(), length);
      total_length += length + 1;

      return total_length;
   }

   const char **get_ipfix_tmplt() const
   {
      static const char *ipfix_template[] = {
         IPFIX_WEBTRAFFIC_TEMPLATE(IPFIX_FIELD_NAMES)
         nullptr
      };
      return ipfix_template;
   }

   std::string get_text() const
   {
      std::ostringstream out;
      out << "hostname=\"" << hostname << "\"";
      return out.str();
   }
};

struct WebtrafficRequestData {
   WebtrafficRequestData(Flow &rec);

   std::string src_ip;
   uint32_t    src_port;
   std::string dst_ip;
   uint32_t    dst_port;
   uint64_t    ts_middle;
};

struct WebtrafficRequestManager {
   WebtrafficRequestManager();

   ~WebtrafficRequestManager();

   const RecordExtWEBTRAFFIC *getRecord(){ return recWebtraffic; }

   void readInfoAboutWebTraffic(WebtrafficRequestData &data);

private:
   void connectToDispatcher(int port);


   int                     sockFd;
   RecordExtWEBTRAFFIC *   recWebtraffic;
   uint succ = 0;
   uint failed = 0;
};

/**
 * \brief Process plugin for parsing WEBTRAFFIC packets.
 */
class WEBTRAFFICPlugin : public ProcessPlugin
{
public:
   WEBTRAFFICPlugin();
   ~WEBTRAFFICPlugin();
   WEBTRAFFICPlugin(const WEBTRAFFICPlugin &p);
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("webtraffic", "Parse WEBTRAFFIC traffic"); }
   std::string get_name() const { return "webtraffic"; }
   RecordExt *get_ext() const { return new RecordExtWEBTRAFFIC(); }
   ProcessPlugin *copy();

   // int pre_create(Packet &pkt);
   // int post_create(Flow &rec, const Packet &pkt);
   // int pre_update(Flow &rec, Packet &pkt);
   // int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);

private:
   WebtrafficRequestManager *manager;
};

}
#endif /* IPXP_PROCESS_WEBTRAFFIC_HPP */

