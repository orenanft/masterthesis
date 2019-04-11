// Load Balancer on SFC: A Load Balancer to a web based network containing it, a NAT with Load
//Balancer, and some Web Servers and Hosts in a private network.
// Author: Renan Freire Tavares
//Based on Felipe Belsholff work available in https://github.com/belsholff/undergraduate-thesis/blob/master/clickOS/LoadBalancer

define($IFLB ens3);
//sets annotations chain ad step for our work
AnnotationInfo(CHAIN 16 1);
AnnotationInfo(STEP 17 1);

// Organizing IPs, networks and MACs from this MicroVM. Or tagging known hosts.
//          name     ip             ipnet               mac
AddressInfo(sfc    10.0.3.107    10.0.3.0/24    FA:16:3E:F9:A4:9C,
            ws1    10.0.1.102,
            ws2    10.0.1.106,
            sff    10.0.3.106,
	          floatingip 10.0.2.156
);

//incoming packets
src :: FromDevice($IFLB);

//outcoming packets
sink :: ARPPrint() -> Queue(1024) -> ToDevice($IFLB);

// click router packet classifier
c :: Classifier(
    12/0806 20/0001, // ARP Requests/queries out 0
    12/0806 20/0002, // ARP Replies out 1
    12/0800, // IP Packets out 2
    -); // other packets - out 3

// Incoming packets from interfaces are going to layer 2 classifier
//input 0.
src -> [0]c; // network port for net0

// ARP Responder definitions. It's useful for host visibility by others in
//networks. It going to answer ARP queries with MAC address based on IP-matched.
//It could contain more than one entry, which means ARP Responders could answer
//queries about another machines and networks. ProxyARP is an application of
//this.
// Connecting queries from classifier to ARPResponder after this, to outside
//world through queues.

// ARP REQUESTS
//ARP queries or requests
arpq :: ARPQuerier(sfc) -> sink;

//ARP replies
arpr :: ARPResponder(sfc) -> sink;

c[0] -> arpr;

// Delivering ARP responses to the ARP queriers.
c[1] -> [1]arpq;

// Other protocol types inside ethernet frames. They are dropped/discarded.
c[3] -> Discard;

// For both: Incoming packets from interfaces are going to layer 2 classifiers
//input 0.


// Mapping used to do load balancing based on Round Robin distribution, with a
//quintuple SIP, SPort, DIP, DPort and Protocol, which means that requests with
//they, are mapped to the same cluster node. It helps in the use of TCP
//connections.
// This mapping is used inside the IPRewriter element below.
// More detailed documentation about rules and this integration here:
//https://github.com/kohler/click/wiki/IPRewriter
ws_mapper :: RoundRobinIPMapper(- - ws1 - 0 1,
                                - - ws2 - 0 1
);

// Simple NAT function. Rewrite packets that cames on it's input ports based on
//some rules in a table. This table receives entries by handlers or general
//lines hardcoded in arguments function. Rules are set twice at time: first one
//about incomming flow and later about outgoing one. Each flow goes out by an
//output port previously defined by rule. Hardcode lines sets inputs and outputs
//ports numbering them by its order in arguments, and are used just when there's
//no rule matched in table.
//IPRewriter hardcoded behaviors:
//1- pattern
//2- drop
//3- pass
// IPRewriter also could receive previously defined static and dinamic tables
//as SourceIPHashMapper (which is our case) or IPRewritterPatterns. More
//detailed documentation in link above.
rewriter :: IPRewriter(ws_mapper);

//IP PACKETS

//checkpaint from classifier
//checkchain :: CheckPaint(1,CHAIN);
//checksfc :: CheckPaint(1,STEP);

// For classifier:
//if the packet has a classifier paint it is redirect to 0 output,
// Ethernet packets are stripped and comes to IP packets, that has its headers
//checked, and send to NAT/LB elements.
//encapsulated (source:sff,dest:loadbalancer),
//painted and encapsulated by ARP querier based on its destination address;
//else to 1 output and to loadbalancer paint check and encapsulated by ARP querier based
//on its destination address.

sfcclassifier :: IPClassifier(
             udp && src port 1, //chain2
             -);

c[2] -> Strip(14) -> CheckIPHeader() -> sfcclassifier;

sfcclassifier[0] -> StripIPHeader() -> Strip(8) -> CheckIPHeader()
	-> [0]rewriter;

sfcclassifier[0] -> Discard;
//checkchain[0] -> checksfc;
//checkchain[1] -> Discard;

//checksfc[0] -> StripIPHeader()
//            -> CheckIPHeader()
//            -> [0]rewriter;

//checksfc[1] -> IPFragmenter(1436) -> [0]arpq;

//For both rewriters:
// As I sad above, here are incomming and outgoing NAT-ed packets. They have
//their checksum recalculated (TCP in this case, others below) and come out
//ready to be send to its destination through ARPQuerier;


rewriter[0] -> SetTCPChecksum()
	    -> UDPIPEncap(sfc:ip,1, sff,2) -> Print("OUT")
            -> [0]arpq;

rewriter[1] -> Print("OUT1") -> Discard;
//SetTCPChecksum()
//            -> SetIPAddress(sfc:ip)
//            -> IPFragmenter(1436) -> [0]arpq;
