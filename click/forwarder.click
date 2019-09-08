// SFC Forwarder: A firewall to a web based network containing it, a NAT with Load
//Balancer, and some Web Servers and Hosts in a private network. This also acts
//as a gateway between 198.51.100.0/24 and 192.0.2.0/24 IETF defined test
//networks, where the entire "public network" are set.
// Author: Renan Freire Tavares

//define($IFSFC 3);  //pci nic

// IPs, networks e MACs.
//          name     ip             ipnet               mac
AddressInfo(sfc        10.0.3.106  10.0.3.0/24    FA:16:3E:C4:00:94,
            firewall   10.0.3.128,
            loadbalancer    10.0.3.107,
            lbsrcip     10.0.3.102,
            router     10.0.3.108
);

//incoming packets
src :: FromDPDKDevice($IFSFC);

//outcoming packets
sink :: ARPPrint() -> ToDPDKDevice($IFSFC);

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


//IP PACKETS

//checkpaints from classifier and for each SF
//checkchain :: CheckPaint(1,CHAIN);
//checkclassifier :: CheckPaint(0,STEP);
//checkfirewall :: CheckPaint(1,STEP);
//checklb :: CheckPaint(2,STEP);

sfcclassifier :: IPClassifier(
             udp && src port 1 && dst port 0, //classifier to firewall
             udp && src port 1 && dst port 1, //firewall to lb
             udp && src port 1 && dst port 2, //lb to ws
             udp && src port 2 && dst port 0, //classifier to firewall
             udp && src port 2 && dst port 1, //firewall to lb-srcip
             udp && src port 2 && dst port 2, //lb-srcip to ws
             udp && src port 3 && dst port 0, ///classifier to firewall
             udp && src port 3 && dst port 1, //firewall to server
             udp && src port 4 && dst port 0, //classifier para o firewall
             udp && src port 4 && dst port 1, //firewall to server
             -);


//ip traffic is stripped, checked and sent to check it has classifier paint
c[2] -> Strip(14) -> CheckIPHeader() -> sfcclassifier;

sfcclassifier[0] -> Print("C1 - IN") -> StripIPHeader() -> Strip(8) -> CheckIPHeader() -> UDPIPEncap(sfc:ip,1,firewall,0) -> [0]arpq;
sfcclassifier[1] -> StripIPHeader() -> Strip(8) -> CheckIPHeader() -> UDPIPEncap(sfc:ip,1,loadbalancer,1) -> [0]arpq;
sfcclassifier[2] -> StripIPHeader() -> Strip(8) -> CheckIPHeader() -> SetTCPChecksum() -> SetIPAddress(router) -> Print("C1- OUT") -> [0]arpq;

sfcclassifier[3] -> Print("C2 - IN") -> StripIPHeader() -> Strip(8) -> CheckIPHeader() -> UDPIPEncap(sfc:ip,2,firewall,0) -> [0]arpq;
sfcclassifier[4] -> StripIPHeader() -> Strip(8) -> CheckIPHeader() -> UDPIPEncap(sfc:ip,2,lbsrcip,1) -> [0]arpq;
sfcclassifier[5] -> StripIPHeader() -> Strip(8) -> CheckIPHeader() -> SetTCPChecksum() -> SetIPAddress(router) -> Print("C2- OUT") -> [0]arpq;

sfcclassifier[6] -> Print("C3 - IN") -> StripIPHeader() -> Strip(8) -> CheckIPHeader() -> UDPIPEncap(sfc:ip,3,firewall,0) -> [0]arpq;
sfcclassifier[7] -> StripIPHeader() -> Strip(8) -> CheckIPHeader() -> SetTCPChecksum() -> SetIPAddress(router) -> Print("C3- OUT") -> [0]arpq;

sfcclassifier[8] -> Print("C4 - IN") -> StripIPHeader() -> Strip(8) -> CheckIPHeader() -> UDPIPEncap(sfc:ip,4,firewall,0) -> [0]arpq;
sfcclassifier[9] -> StripIPHeader() -> Strip(8) -> CheckIPHeader() -> SetTCPChecksum() -> SetIPAddress(router) -> Print("C4- OUT") -> [0]arpq;

sfcclassifier[10] -> Discard;

//checkchain[0] -> Print("CHAIN1") -> checkclassifier;
//checkchain[1] -> Print("DISCARD") -> Discard;

//if the packet has a classifier paint it is redirect to 0 output,
//encapsulated (source:sff,dest:firewall), painted and encapsulated by ARP querier based
//on its destination address;
//else to 1 output and to firewall paint check
//checkclassifier[0] -> Print("STEP1") -> StripIPHeader() -> CheckIPHeader() -> IPEncap(4, sfc:ip, firewall) -> Paint(1,CHAIN) -> Paint(0,STEP) -> IPFragmenter(1436) -> [0]arpq;
//checkclassifier[1] -> [0]checkfirewall;

//if the packet has a firewall paint it is redirect to 0 output,
//encapsulated (source:sff,dest:loadbalancer), painted and encapsulated by ARP querier based
//on its destination address;
//else to 1 output and to loadbalancer paint check
//checkfirewall[0] -> Print("STEP2") -> StripIPHeader() -> CheckIPHeader() -> IPEncap(4, sfc:ip, loadbalancer) -> Paint(1,CHAIN) -> Paint(1,STEP) -> IPFragmenter(1436) -> [0]arpq;
//checkfirewall[1] -> IPFragmenter(1450) -> [0]checklb;

//if the packet has a loadbalancer paint it is redirect to 0 output,
//is stripped, checked and encapsulated by ARP querier based
//on its destination address;
//else to 1 output and encapsulated by ARP querier based
//on its destination address.
//checklb[0] ->  Print("OUT") -> StripIPHeader() -> CheckIPHeader() -> IPFragmenter(1436) -> [0]arpq;
//checklb[1] -> Print("OUTDISCARD") -> Discard;
