#ifndef CLICK_SFCEncap_HH
#define CLICK_SFCEncap_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
#include <clicknet/udp.h>
CLICK_DECLS

class SFCEncap : public Element { public:

    SFCEncap() CLICK_COLD;
    ~SFCEncap() CLICK_COLD;

    const char *class_name() const	{ return "SFCEncap"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const		{ return "A"; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    bool can_live_reconfigure() const	{ return true; }
    void add_handlers() CLICK_COLD;

    Packet *simple_action(Packet *);

  private:

    struct in_addr _saddr;
    struct in_addr _daddr;
    uint16_t _chain;
    uint16_t _step;
    bool _cksum;
    bool _use_dst_anno;
#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
    bool _aligned;
    bool _checked_aligned;
#endif
    atomic_uint32_t _id;

    static String read_handler(Element *, void *) CLICK_COLD;

};

CLICK_ENDDECLS
#endif
