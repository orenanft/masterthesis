// Firewall on SFC: A firewall to a web based network containing it.
// Author: Renan Freire Tavares
//Based on Felipe Belsholff work available in https://github.com/belsholff/undergraduate-thesis/blob/master/clickOS/LoadBalancer;

define($IFFRW ens3);
//sets annotations chain ad step for our work
AnnotationInfo(CHAIN 16 1);
AnnotationInfo(STEP 17 1);

// Organizing IPs, networks and MACs from this MicroVM. Or tagging known hosts.
//          name             ip           ipnet              mac
AddressInfo(sfc    10.0.3.128    10.0.3.0/24    FA:16:3E:73:B2:BC,
            sff    10.0.3.106,
	          floatingip  10.0.2.156
);

//incoming packets
src :: FromDevice($IFFRW);

//outcoming packets
sink :: Queue(1024) -> ToDevice($IFFRW);

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

// Firewall application accepting only http/https requests to floatingip.
webFilter :: IPFilter(allow dst floatingip && dst port 80 && dst port 443,
                        drop all)

// Firewall application accepting only http responses (through dynamic ports)
//to entire net0 from natlb.
// OSes dynamic ports list:
//Linux     - 32768-61000
//WinVista  - \/
//Win7      - \/
//WinSrv08  - \/
//FreeBSD4.6- \/
//IANA      - 49152-65535
//BSD       - \/
//WindowsXP - \/
//WinSrv03  - 1025-5000
//Win8      - \/
//Win8.1    - \/
//Win10     -  ?
//webFilterOUT :: IPFilter(allow src natlb && dst net0:ipnet && dst port >= 32768 && dst port <= 61000,
//                         drop all) //Como fazer para ser stateful?

//IP PACKETS

//checkpaint from classifier
checkchain :: CheckPaint(1,CHAIN);
checksfc :: CheckPaint(0,STEP);

// For classifier:

//if the packet has a classifier paint it is redirect to 0 output,
// Ethernet packets are stripped and comes to IP packets, that has its headers
//checked, filtered by incomming firewall; encapsulated (source:sff,dest:loadbalancer),
//painted and encapsulated by ARP querier based on its destination address;
//else to 1 output and to loadbalancer paint check and encapsulated by ARP querier based
//on its destination address.
c[2] -> StripIPHeader() -> CheckIPHeader() -> checkchain;

checkchain[0] -> checksfc;
checkchain[1] -> Discard;

checksfc[0] -> Strip(14) -> CheckIPHeader()
            -> webFilter
            -> IPEncap(4, sfc:ip, sff) -> Paint(1,CHAIN) -> Paint(1,STEP) -> [0]arpq;
checksfc[1] -> [0]arpq;
