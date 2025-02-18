/**
 * \file basicplus.cpp
 * \brief Plugin for parsing basicplus traffic.
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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

#include "basicplus.hpp"

namespace ipxp {

int RecordExtBASICPLUS::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("basicplus", [](){return new BASICPLUSPlugin();});
   register_plugin(&rec);
   RecordExtBASICPLUS::REGISTERED_ID = register_extension();
}

BASICPLUSPlugin::BASICPLUSPlugin()
{
}

BASICPLUSPlugin::~BASICPLUSPlugin()
{
   close();
}

void BASICPLUSPlugin::init(const char *params)
{
}

void BASICPLUSPlugin::close()
{
}

ProcessPlugin *BASICPLUSPlugin::copy()
{
   return new BASICPLUSPlugin(*this);
}

int BASICPLUSPlugin::post_create(Flow &rec, const Packet &pkt)
{
   RecordExtBASICPLUS *p = new RecordExtBASICPLUS();

   rec.add_extension(p);

   p->ip_ttl[0]  = pkt.ip_ttl;
   p->ip_flg[0]  = pkt.ip_flags;
   p->tcp_mss[0] = pkt.tcp_mss;
   p->tcp_opt[0] = pkt.tcp_options;
   p->tcp_win[0] = pkt.tcp_window;
   if (pkt.tcp_flags == 0x02) { // check syn packet
      p->tcp_syn_size = pkt.ip_len;
   }

   return 0;
}

int BASICPLUSPlugin::pre_update(Flow &rec, Packet &pkt)
{
   RecordExtBASICPLUS *p = (RecordExtBASICPLUS *) rec.get_extension(RecordExtBASICPLUS::REGISTERED_ID);
   uint8_t dir = pkt.source_pkt ? 0 : 1;

   if (p->ip_ttl[dir] < pkt.ip_ttl) {
      p->ip_ttl[dir] = pkt.ip_ttl;
   }
   if (dir && !p->dst_filled) {
      p->ip_ttl[1]  = pkt.ip_ttl;
      p->ip_flg[1]  = pkt.ip_flags;
      p->tcp_mss[1] = pkt.tcp_mss;
      p->tcp_opt[1] = pkt.tcp_options;
      p->tcp_win[1] = pkt.tcp_window;
      p->dst_filled = true;
   }
   return 0;
}

}
