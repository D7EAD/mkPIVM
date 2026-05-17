// empty TU. cipher code is split across vm_isa.cpp and codec.cpp. cmake needed
// something to point at, so here we are
namespace mkpivm { 
    namespace detail_crypto { 
        inline int link_anchor() { 
            return 0; 
        }
    }
}