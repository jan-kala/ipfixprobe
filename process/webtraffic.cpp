/**
 * \file webtraffic.cpp
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

#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "webtraffic.hpp"

namespace ipxp {

int RecordExtWEBTRAFFIC::REGISTERED_ID = -1;

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("webtraffic", [](){return new WEBTRAFFICPlugin();});
   register_plugin(&rec);
   RecordExtWEBTRAFFIC::REGISTERED_ID = register_extension();
}

WEBTRAFFICPlugin::WEBTRAFFICPlugin() : manager(nullptr)
{
   // std::cout << "ctor" << std::endl;
}

WEBTRAFFICPlugin::WEBTRAFFICPlugin(const WEBTRAFFICPlugin &p)
{
   // std::cout << "ctor 2" << std::endl;

   init(nullptr);
}

WEBTRAFFICPlugin::~WEBTRAFFICPlugin()
{
   // std::cout << "destruct" << std::endl;

   close();
}

void WEBTRAFFICPlugin::init(const char *params)
{
   // std::cout << "init" << std::endl;
   manager = new WebtrafficRequestManager();
}

void WEBTRAFFICPlugin::close()
{
   // std::cout << "close" << std::endl;

   if (manager != nullptr){
      delete manager;
      manager = nullptr;
   }
}

ProcessPlugin *WEBTRAFFICPlugin::copy()
{
   // std::cout << "copy" << std::endl;

   return new WEBTRAFFICPlugin(*this);
}

void WEBTRAFFICPlugin::pre_export(Flow &rec)
{
   // std::cout << "pre_export" << std::endl;

   // tady prekroutim flow data na to co potrebuju:
   WebtrafficRequestData data(rec);
   
   // request managerovi predhodim zadost s daty vyssie
      // pokud uspeje, tak vytvorim novy record jak v osquer
      // rec.add_extension(record);
   manager->readInfoAboutWebTraffic(data);

}

WebtrafficRequestData::WebtrafficRequestData(Flow &rec)
{
   if (rec.ip_version == 4){
      char ipString[INET_ADDRSTRLEN];

      inet_ntop(AF_INET, &(rec.src_ip.v4), ipString, INET_ADDRSTRLEN);
      src_ip = ipString;

      inet_ntop(AF_INET, &(rec.dst_ip.v4), ipString, INET_ADDRSTRLEN);
      dst_ip = ipString;
   } else {
      char ipString[INET6_ADDRSTRLEN];

      inet_ntop(AF_INET6, &(rec.src_ip.v6), ipString, INET6_ADDRSTRLEN);
      src_ip = ipString;

      inet_ntop(AF_INET6, &(rec.dst_ip.v6), ipString, INET6_ADDRSTRLEN);
      dst_ip = ipString;
   }

   src_port = rec.src_port;
   dst_port = rec.dst_port;
   uint64_t ts_start_micro = (rec.time_first.tv_sec * (uint64_t)1000000) + (rec.time_first.tv_usec); 
   uint64_t ts_end_micro = (rec.time_last.tv_sec * (uint64_t)1000000) + (rec.time_last.tv_usec); 

   ts_middle = (ts_start_micro + ts_end_micro) / 2;
}

WebtrafficRequestManager::WebtrafficRequestManager()
{
   // std::cout << "Request Manager ctor" << std::endl;
}

WebtrafficRequestManager::~WebtrafficRequestManager()
{
   // std::cout << "Request Manager dtor" << std::endl;
   close(sockFd);
   sockFd = 0;
}

void WebtrafficRequestManager::connectToDispatcher(int port)
{
   int sock = 0;
   struct sockaddr_in remote;

   sock = socket(AF_INET, SOCK_STREAM, 0);
   if (sock == -1){
      throw std::runtime_error("Webtraffic: Failed to create socket.");
   }

   remote.sin_family = AF_INET;
   inet_pton(AF_INET, "127.0.0.1", &(remote.sin_addr.s_addr));
   remote.sin_port = htons(port);
   
   if (connect(sock, (struct sockaddr*)&remote, sizeof(remote)) == -1){
      throw std::runtime_error("Webtraffic: Failed to connect to the client!");
   }

   sockFd = sock;
}

void WebtrafficRequestManager::readInfoAboutWebTraffic(WebtrafficRequestData &data)
{
   // connect 
   connectToDispatcher(50559);

   // construct request
   json newRequest;
   newRequest["srcIp"] = data.src_ip;
   newRequest["srcPort"] = data.src_port;
   newRequest["dstIp"] = data.dst_ip;
   newRequest["dstPort"] = data.dst_port;
   newRequest["timestamp"] = data.ts_middle;

   // transfer json request to data
   auto response_string = newRequest.dump();
   uint32_t payload_data_size = response_string.length();
   size_t total_payload_size = 4 + payload_data_size;

   char payload[total_payload_size];
   memset(payload, '\0', total_payload_size);

   auto nbo = htonl(payload_data_size);
   memcpy(payload, &nbo, 4);
   memcpy(payload+4, response_string.data(), response_string.length());
  
   // send it!
   if (send(sockFd, payload, total_payload_size, 0) < 0){
      throw std::runtime_error("Webtraffic: Failed to send request to dispatcher");
   }

   // read response
   size_t response_len = 0;
   uint32_t len_buffer;

   response_len = recv(sockFd, &len_buffer, 4, 0);
   if (response_len == -1){
      throw std::runtime_error("Webtrafic: Failed to receive response length.");
   }

   auto messageSize = ntohl(len_buffer);
   char response_json[messageSize];
   memset(response_json, '\0', messageSize);

   int dataLen = 0;
   while (dataLen != messageSize){
      auto recvLen = recv(sockFd, response_json+dataLen, messageSize-dataLen, 0);

      if (recvLen == -1){
         throw std::runtime_error("Webtraffic: Error while reading response");
      }

      dataLen += recvLen;
   }

   json response = json::parse(std::string(response_json, messageSize));

   if (!response["serverNameIndication"].empty() && !response["httpRequests"].is_null()){
      std::cout << response["serverNameIndication"].get<std::string>() << std::endl;
      succ++;
   } else {
      failed++;
   }
   auto rate = (float(succ) / (float(succ) + float(failed))) * 100;

   std::cout << "rate: " << rate << "% [succ:" << succ << ", failed: "<< failed << "]" << std::endl;

   close(sockFd);
}

}

