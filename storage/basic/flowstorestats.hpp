/**
 * \file cache.hpp
 * \brief "FlowStore" Flow store abstraction
 * \author Tomas Benes <tomasbenes@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2014-2016 CESNET
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
 * This software is provided ``as is'', and any express or implied
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
#ifndef IPXP_FLOW_STORE_STATS_HPP
#define IPXP_FLOW_STORE_STATS_HPP

#include <string>
#include <memory>
#include <sstream>
#include <vector>

namespace ipxp {

class FlowStoreStat {
    std::string m_name;
public:
    enum Type {
        Leaf = 0,
        Array
    };
    typedef std::shared_ptr<FlowStoreStat> Ptr;
    typedef std::vector<Ptr> PtrVector;

    FlowStoreStat(std::string name) : m_name(name) {}
    virtual Type getType() { return Type::Leaf; }
    virtual std::string getName() { return m_name; }
    virtual std::string getValue() { throw std::logic_error("Not supported"); return 0; }
    virtual PtrVector getArray() { throw std::logic_error("Not supported"); return PtrVector(); };
};

class FlowStoreStatVector : public FlowStoreStat {
    FlowStoreStat::PtrVector m_vec;
public:
    FlowStoreStatVector(std::string name, FlowStoreStat::PtrVector vec = FlowStoreStat::PtrVector()) : FlowStoreStat(name), m_vec(vec) {}
    Type getType() { return Type::Array; };
    PtrVector getArray() { return m_vec; };
};

template<typename T>
class FlowStoreStatPrimitive : public FlowStoreStat {
    T m_prim;
    std::stringstream ss;
public:
    FlowStoreStatPrimitive(std::string name, T prim) : FlowStoreStat(name), m_prim(prim) {}
    Type getType() { return Type::Leaf; };
    std::string getValue() {
        ss.clear();
        ss << m_prim;
        return ss.str();
    }
};

template<typename T>
FlowStoreStat::Ptr make_FSStatPrimitive(std::string name, T prim) {
    return std::make_shared<FlowStoreStatPrimitive<T>>(name, prim);
}

FlowStoreStat::Ptr FlowStoreStatExpand(FlowStoreStat::Ptr ptr, FlowStoreStat::PtrVector expand);
void FlowStoreStatJSON(std::ostream &out, FlowStoreStat::Ptr ptr);

}

#endif //IPXP_FLOW_STORE_STATS_HPP