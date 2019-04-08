// SFC Classifier: A sfc packet classifier based on some rules. This also acts
//as a gateway between 10.0.0.0/24, 10.0.3.0/24 and 10.0.1.0/24.
// Author: Renan Freire Tavares

define($IFNET0 ens6);
define($IFSFC ens7);
define($IFNET1 ens8);
define($IFCLIENT ens9);
//sets annotations chain ad step for our work
AnnotationInfo(CHAIN 16 1);
AnnotationInfo(STEP 17 1);

// IPs, networks e MACs.
//          name     ip             ipnet               mac
AddressInfo(net0    10.0.0.5    10.0.0.0/24    FA:16:3E:2C:5C:46,
            sfc     10.0.3.108  10.0.3.0/24    FA:16:3E:4C:AA:C7,
            net1    10.0.1.121  10.0.1.0/24    FA:16:3E:87:17:6B,
            client  10.0.5.3  10.0.5.0/24      FA:16:3E:77:A3:34,
            sff     10.0.3.106,
	          public  10.0.2.156  10.0.2.0/24,
            ws1    10.0.1.102,
            ws2    10.0.1.106
);

//incoming packets
src1 :: FromDevice($IFNET0);
src2 :: FromDevice($IFSFC);
src3 :: FromDevice($IFNET1);
src4 :: FromDevice($IFCLIENT);

//outcoming packets
sink1   :: ARPPrint() -> Queue(1024) -> ToDevice($IFNET0);
sink2   :: ARPPrint() -> Queue(1024) -> ToDevice($IFSFC);
sink3   :: ARPPrint() -> Queue(1024) -> ToDevice($IFNET1);
sink4   :: ARPPrint() -> Queue(1024) -> ToDevice($IFCLIENT);

// click router packet classifiers
c1,c2,c3,c4 :: Classifier(
    12/0806 20/0001, // ARP Requests/queries out 0
    12/0806 20/0002, // ARP Replies out 1
    12/0800, // IP Packets out 2
    -); // other packets - out 3

// For both: Incoming packets from interfaces are going to layer 2 classifiers
//input 0.
src1 -> [0]c1; // First network port for net0
src2 -> [0]c2; // for netsfc;
src3 -> [0]c3; // for net1;
src4 -> [0]c4; // for client;

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
arpq4 :: ARPQuerier(client) -> sink4;

//ARP replies
arpr1 :: ARPResponder(net0) -> sink1;
arpr2 :: ARPResponder(sfc) -> sink2;
arpr3 :: ARPResponder(net1) -> sink3;
arpr4 :: ARPResponder(client) -> sink4;

c1[0] -> arpr1;
c2[0] -> arpr2;
c3[0] -> arpr3;
c4[0] -> arpr4;

// Delivering ARP responses to the ARP queriers.
c1[1] -> [1]arpq1;
c2[1] -> [1]arpq2;
c3[1] -> [1]arpq3;
c4[1] -> [1]arpq4;

// Other protocol types inside ethernet frames. They are dropped/discarded.
c1[3] -> Discard;
c2[3] -> Discard;
c3[3] -> Discard;
c4[3] -> Discard;

//IP PACKETS

//Element with four outputs to classify IP packets.
//The first output is for net0 packets;
//The second output is for sfc packets;
//and the third output is for net1 packets.
//The last output is for all other IP packets.
sfcclassifier :: IPClassifier(//dst host public:ip,
             dst host client:ip,
	     dst net net0,
             dst net sfc,
             dst net net1,
             //src host ws1 && src net != net0 && src net != sfc && src net != net1,
             //src host ws2 && src net != net0 && src net != sfc && src net != net1,
             src host ws1 && dst net client,
             src host ws2 && dst net client,
             //dst net client,
             -);

//traffic from net0, net1 and sfc will go to sfcclassifier
c1[2] -> Strip(14) -> CheckIPHeader() -> [0]sfcclassifier;
c2[2] -> Strip(14) -> CheckIPHeader() -> [0]sfcclassifier;
c3[2] -> Strip(14) -> CheckIPHeader() -> [0]sfcclassifier;
c4[2] -> Strip(14) -> CheckIPHeader() -> [0]sfcclassifier;

//redirecting/routing traffic from net0
//now the traffic from net0 to net1 will follow the sfc rules
//Thus, net1 traffic will be routed to sfc network
//The ip packet will be encapsulated and the header (source: classifier ip, dest: sff ip)
//Finally the paint annotation will indicate the chain and the step(third element is unused)

//define($ip client:ip);
rewriter :: IPRewriter(pattern client:ip - - - 0 1);

checklen1 :: CheckLength(1400);
checklen2 :: CheckLength(1400);
checklen3 :: CheckLength(1400);
checklen4 :: CheckLength(1400);
checklensfc :: CheckLength(1400);

checklen1[0] -> [0]arpq1;
checklen1[1] -> Print("LARGE") -> IPFragmenter(1400) -> [0]arpq1;

checklen2[0] -> IPPrint(CONTENTS ASCII) -> [0]arpq2;
checklen2[1] -> Print("LARGE") -> IPFragmenter(1400) -> [0]arpq2;

checklen3[0] -> [0]arpq3;
checklen3[1] -> Print("LARGE") -> IPFragmenter(1400) -> [0]arpq3;

checklen4[0] -> IPPrint(CONTENTS ASCII) -> Print("out") -> [0]arpq4;
checklen4[1] -> Print("LARGE") -> IPFragmenter(1400) -> [0]arpq4;

checklensfc[0] -> IPPrint(CONTENTS ASCII) -> [0]arpq2;
checklensfc[1] -> Print("LARGE") -> IPFragmenter(1400) -> [0]arpq2;

sfcclassifier[0] ->  UDPIPEncap(sfc:ip,1,sff,0) -> checklensfc;
sfcclassifier[1] ->  Print("1") -> checklen1;
sfcclassifier[2] ->  Print("2") -> checklen2;
sfcclassifier[3] ->  Print("3") -> checklen3;
//sfcclassifier[4] -> SetTCPChecksum() -> SetIPAddress(public:ip) -> checklen1;
//sfcclassifier[4] ->  Print("4") -> IPPrint(CONTENTS ASCII) -> Print("in") -> IPGWOptions(client:ip) -> FixIPSrc(client:ip) -> checklen4;
sfcclassifier[4] ->  Print("4") -> IPPrint(CONTENTS ASCII) -> Print("in") -> [0]rewriter;
sfcclassifier[5] ->  Print("5") -> IPPrint(CONTENTS ASCII) -> Print("in") -> [0]rewriter;
//sfcclassifier[6] -> Print("6") -> checklen4;
sfcclassifier[6] ->  Print("7") -> Discard;

rewriter[0] -> SetTCPChecksum() -> checklen4;
rewriter[1] -> Discard;
