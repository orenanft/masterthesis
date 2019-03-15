// SFC Classifier: A sfc packet classifier based on some rules. This also acts
//as a gateway between 10.0.0.0/24, 10.0.3.0/24 and 10.0.1.0/24.
// Author: Renan Freire Tavares

define($IFNET0 ens3);
define($IFSFC ens4);
define($IFNET1 ens5);
//sets annotations chain ad step for our work
AnnotationInfo(CHAIN 16 1);
AnnotationInfo(STEP 17 1);

// IPs, networks e MACs.
//          name     ip             ipnet               mac
AddressInfo(net0    10.0.0.7    10.0.0.0/24    FA:16:3E:2C:5C:46,
            sfc     10.0.3.117  10.0.3.0/24    FA:16:3E:4C:AA:C7,
            net1    10.0.1.104  10.0.1.0/24    FA:16:3E:87:17:6B,
            sff     10.0.3.106,
	          public  10.0.2.156  10.0.2.0/24,
            loadb   10.0.3.107
);

//incoming packets
src1 :: FromDevice($IFNET0);
src2 :: FromDevice($IFSFC);
src3 :: FromDevice($IFNET1);

//outcoming packets
sink1   :: Queue(1024) -> ToDevice($IFNET0);
sink2   :: Queue(1024) -> ToDevice($IFSFC);
sink3   :: Queue(1024) -> ToDevice($IFNET1);

// click router packet classifiers
c1,c2,c3 :: Classifier(
    12/0806 20/0001, // ARP Requests/queries out 0
    12/0806 20/0002, // ARP Replies out 1
    12/0800, // IP Packets out 2
    -); // other packets - out 3

// For both: Incoming packets from interfaces are going to layer 2 classifiers
//input 0.
src1 -> [0]c1; // First network port for net0
src2 -> [0]c2; // for netsfc;
src3 -> [0]c3; // for net1;

// ARP Responder definitions. It's useful for host visibility by others in
//networks. It going to answer ARP queries with MAC address based on IP-matched.
//It could contain more than one entry, which means ARP Responders could answer
//queries about another machines and networks. ProxyARP is an application of
//this.
// Connecting queries from classifier to ARPResponder after this, to outside
//world through queues.

// ARP REQUESTS
//ARP queries or requests
arpq1 :: ARPQuerier(net0) -> sink1;
arpq2 :: ARPQuerier(sfc) -> sink2;
arpq3 :: ARPQuerier(net1) -> sink3;
//ARP replies
arpr1 :: ARPResponder(net0) -> sink1;
arpr2 :: ARPResponder(sfc) -> sink2;
arpr3 :: ARPResponder(net1) -> sink3;

c1[0] -> arpr1;
c2[0] -> arpr2;
c3[0] -> arpr3;

// Delivering ARP responses to the ARP queriers.
c1[1] -> [1]arpq1;
c2[1] -> [1]arpq2;
c3[1] -> [1]arpq3;

// Other protocol types inside ethernet frames. They are dropped/discarded.
c1[3] -> Discard;
c2[3] -> Discard;
c3[3] -> Discard;


//IP PACKETS

//Element with four outputs to classify IP packets.
//The first output is for net0 packets;
//The second output is for sfc packets;
//and the third output is for net1 packets.
//The last output is for all other IP packets.
sfcclassifier :: IPClassifier(dst host public:ip,
	           dst host net0:ip,
             dst host sfc:ip,
             dst host net1:ip,
             src host loadb && dest net != net0 && dest net != sfc && dest net != net1,
             -);

//traffic from net0, net1 and sfc will go to sfcclassifier
c1[2] -> Strip(14) -> CheckIPHeader() -> [0]sfcclassifier;
c3[2] -> Strip(14) -> CheckIPHeader() -> [0]sfcclassifier;
c2[2] -> Strip(14) -> CheckIPHeader() -> [0]sfcclassifier;


//redirecting/routing traffic from net0
//now the traffic from net0 to net1 will follow the sfc rules
//Thus, net1 traffic will be routed to sfc network
//The ip packet will be encapsulated and the header (source: classifier ip, dest: sff ip)
//Finally the paint annotation will indicate the chain and the step(third element is unused)
sfcclassifier[0] -> IPEncap(4, net0:ip, sff) -> Paint(1,CHAIN) -> Paint(0,STEP) -> [0]arpq2;
sfcclassifier[1] -> [0]arpq1;
sfcclassifier[2] -> [0]arpq2;
sfcclassifier[3] -> [0]arpq3;
sfcclassifier[4] -> SetTCPChecksum() -> SetIPAddress(public:ip) -> [0]arpq1;
sfcclassifier[5] -> Discard;
