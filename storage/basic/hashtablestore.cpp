#include "hashtablestore.hpp"
#include "flowcache.hpp"

namespace ipxp {

HTFlowsStorePacketInfo HTFlowsStorePacketInfo::from_packet(Packet &pkt, bool inverse) {
    flow_key_t key;
    key.proto = pkt.ip_proto;
    key.ip_version = pkt.ip_version;
    key.src_port = !inverse ? pkt.src_port : pkt.dst_port;
    key.dst_port = !inverse ? pkt.dst_port : pkt.src_port;
    if (pkt.ip_version == IP::v4) {
        key.ip.v4.src_ip = !inverse ? pkt.src_ip.v4 : pkt.dst_ip.v4;
        key.ip.v4.dst_ip = !inverse ? pkt.dst_ip.v4 : pkt.src_ip.v4;
    } else if (pkt.ip_version == IP::v6) {
        memcpy(key.ip.v6.src_ip.data(), !inverse ? pkt.src_ip.v6 : pkt.dst_ip.v6, sizeof(pkt.src_ip.v6));
        memcpy(key.ip.v6.dst_ip.data(), !inverse ? pkt.dst_ip.v6 : pkt.src_ip.v6, sizeof(pkt.dst_ip.v6));
    }
    return HTFlowsStorePacketInfo(pkt, inverse, key);
}

void HTFlowStore::init(HashTableStoreParser& parser)
{
   m_cache_size = parser.m_cache_size;
   m_line_size = parser.m_line_size;
   m_line_mask = (m_cache_size - 1) & ~(m_line_size - 1);
   m_line_new_idx = m_line_size / 2;

   if (m_line_size > m_cache_size) {
      throw PluginError("flow cache line size must be greater or equal to cache size");
   }
   if (m_cache_size == 0) {
      throw PluginError("flow cache won't properly work with 0 records");
   }

   try {
      m_flow_table.resize(m_cache_size);
      m_flow_records.resize(m_cache_size);
      for (uint32_t i = 0; i < m_cache_size; i++) {
         m_flow_table[i] = &m_flow_records[i];
      }
   } catch (std::bad_alloc &e) {
      throw PluginError("not enough memory for flow cache allocation");
   }

#ifdef FLOW_CACHE_STATS
   m_lookups = 0;
   m_lookups2 = 0;
#endif /* FLOW_CACHE_STATS */
}

HTFlowStore::packet_info HTFlowStore::prepare(Packet &pkt, bool inverse = false)
{
   return HTFlowsStorePacketInfo::from_packet(pkt, inverse);
}

HTFlowStore::accessor HTFlowStore::lookup(packet_info &pkt)
{
    FlowIndex flowRow_index = makeRowIndex(pkt.getHash());
    FlowIndex flowIndex = searchLine(flowRow_index, pkt.getHash());
    if(flowIndex.valid) {
        auto ind = (m_flow_table.begin() + flowIndex.flow_index);
        return ind;
    }
    return lookup_end();
}

HTFlowStore::accessor HTFlowStore::lookup_empty(packet_info &pkt)
{
    FlowIndex flowRow_index = makeRowIndex(pkt.getHash());
    FlowIndex flowIndex = searchEmptyLine(flowRow_index);
    if(flowIndex.valid) {
        auto ind = (m_flow_table.begin() + flowIndex.flow_index);
        return ind;
    }
    return lookup_end();
}

HTFlowStore::accessor HTFlowStore::free(packet_info &pkt)
{
    FlowIndex flowRow_index = makeRowIndex(pkt.getHash());
    return (m_flow_table.begin()+flowRow_index.line_index+m_line_size-1);
}

HTFlowStore::accessor HTFlowStore::put(const accessor &acc)
{
    FlowIndex flowIndex = fromAccessor(acc);
    moveToFront(flowIndex);
    return (m_flow_table.begin() + flowIndex.line_index);
}

HTFlowStore::accessor HTFlowStore::index_export(const accessor &acc, FlowRingBuffer &rb)
{
    FlowIndex flowRow_index = fromAccessor(acc);
    FCRecord *sw_rec = rb.put(m_flow_table[flowRow_index.flow_index]);
    m_flow_table[flowRow_index.flow_index] = sw_rec;
    sw_rec->erase();
    return (m_flow_table.begin() + flowRow_index.flow_index);
}

HTFlowStore::accessor HTFlowStore::iter_export(const iterator &iter, FlowRingBuffer &rb)
{
    uint32_t flow_index = iter - this->begin();
    FCRecord *sw_rec = rb.put(m_flow_table[flow_index]);
    m_flow_table[flow_index] = sw_rec;
    sw_rec->erase();
    return (m_flow_table.begin() + flow_index);
}
}