// SFC Classifier: A sfc packet classifier based on some rules. This also acts
//as a gateway between 10.0.0.0/24, 10.0.3.0/24 and 10.0.1.0/24.
// Author: Renan Freire Tavares

//define($IFNET0 3); //pci nic
//define($IFSFC 3); //pci nic
//define($IFNET1 3); //pci nic
//define($IFCLIENT 3); //pci nic

// IPs, networks e MACs.
//          name     ip             ipnet               mac
AddressInfo(net0    10.0.0.5    10.0.0.0/24    FA:16:3E:2C:5C:46,
            sfc     10.0.3.108  10.0.3.0/24    FA:16:3E:4C:AA:C7,
            net1    10.0.1.121  10.0.1.0/24    FA:16:3E:87:17:6B,
            client  10.0.5.3  10.0.5.0/24      FA:16:3E:77:A3:34,
            cchain2 10.0.5.20,
            cchain3 10.0.5.21,
            cchain4 10.0.5.22,
            sff     10.0.3.106,
	          public  10.0.2.156  10.0.2.0/24,
            ws1    10.0.1.102,
            ws2    10.0.1.106
);

//incoming packets
src1 :: FromDPDKDevice($IFNET0);
src2 :: FromDPDKDevice($IFSFC);
src3 :: FromDPDKDevice($IFNET1);
src4 :: FromDPDKDevice($IFCLIENT);

//outcoming packets
sink1   :: ARPPrint() -> ToDPDKDevice($IFNET0);
sink2   :: ARPPrint() -> ToDPDKDevice($IFSFC);
sink3   :: ARPPrint() -> ToDPDKDevice($IFNET1);
sink4   :: ARPPrint() -> ToDPDKDevice($IFCLIENT);

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

//Element with n outputs to classify IP packets.
//Output 0 is for incoming chain1 packets
//Output 1 is for incoming chain2 packets
//Output 2 is for incoming chain3 packets
//Output 3 is for incoming chain4 packets
//Output 4 is for net0 packets
//Output 5 is for sfc packets
//Output 6 is for net1 packets.
//Output 7 is for outcoming chain1 packets.
//Output 8 is for outcoming chain2 packets.
//Output 9 is for outcoming chain3 packets.
//Output 10 is for outcoming chain4 packets.
//Output 11 is for all other IP packets.
sfcclassifier :: IPClassifier(
             src net != net1 && dst host client:ip,
             src net != net1 && dst host cchain2:ip,
             src net != net1 && dst host cchain3:ip,
             src net != net1 && dst host cchain4:ip,
	           dst net net0,
             dst net sfc,
             dst net net1,
             (src host ws1 || src host ws2) && dst host client:ip,
             (src host ws1 || src host ws2) && dst host cchain2:ip,
             src host ws1 && dst net client,
             src host ws2 && dst net client,
             -);

//traffic from net0, sfc, net1 and client will go to sfcclassifier
c1[2] -> Strip(14) -> CheckIPHeader() -> [0]sfcclassifier;
c2[2] -> Strip(14) -> CheckIPHeader() -> [0]sfcclassifier;
c3[2] -> Strip(14) -> CheckIPHeader() -> [0]sfcclassifier;
c4[2] -> Strip(14) -> CheckIPHeader() -> [0]sfcclassifier;

//redirecting/routing traffic from net0
//now the traffic from net0 to net1 will follow the sfc rules
//Thus, net1 traffic will be routed to sfc network
//The ip packet will be encapsulated and the header (source: classifier ip, dest: sff ip)
//Finally the paint annotation will indicate the chain and the step(third element is unused)

rewriterChain1IN :: IPRewriter(pattern client:ip - - - 0 1);
rewriterChain2IN :: IPRewriter(pattern cchain2:ip - - - 0 1);
rewriterChain3 :: IPRewriter(pattern - - ws1 - 0 1);
rewriterChain4 :: IPRewriter(pattern - - ws2 - 0 1);

rewriterChain1OUT :: IPRewriter(pattern client:ip - - - 0 1);
rewriterChain2OUT :: IPRewriter(pattern cchain2:ip - - - 0 1);

checklen1 :: CheckLength(1400);
checklen2 :: CheckLength(1400);
checklen3 :: CheckLength(1400);
checklen4 :: CheckLength(1400);

checklen1[0] -> [0]arpq1;
checklen1[1] -> IPFragmenter(1400) -> [0]arpq1;

checklen2[0] -> [0]arpq2;
checklen2[1] -> IPFragmenter(1400) -> [0]arpq2;

checklen3[0] -> [0]arpq3;
checklen3[1] -> IPFragmenter(1400) -> [0]arpq3;

checklen4[0] -> [0]arpq4;
checklen4[1] -> IPFragmenter(1400) -> [0]arpq4;

sfcclassifier[0] -> [0]rewriterChain1IN;
sfcclassifier[1] -> [0]rewriterChain2IN;
sfcclassifier[2] -> [0]rewriterChain3;
sfcclassifier[3] -> [0]rewriterChain4;
sfcclassifier[4] -> checklen1;
sfcclassifier[5] -> checklen2;
sfcclassifier[6] -> checklen3;
sfcclassifier[7] -> [0]rewriterChain1OUT;
sfcclassifier[8] -> [0]rewriterChain2OUT;
sfcclassifier[9] -> [0]rewriterChain3;
sfcclassifier[10] -> [0]rewriterChain4;
sfcclassifier[11] -> Discard;

rewriterChain1IN[0] -> UDPIPEncap(sfc:ip,1,sff,0) -> checklen2;
rewriterChain1IN[1] -> SetTCPChecksum() -> checklen4;

rewriterChain2IN[0] -> UDPIPEncap(sfc:ip,2,sff,0) -> checklen2;
rewriterChain2IN[1] -> SetTCPChecksum() -> checklen4;

rewriterChain3[0] -> UDPIPEncap(sfc:ip,3,sff,0) -> checklen2;
rewriterChain3[1] -> SetTCPChecksum() -> checklen4;

rewriterChain4[0] -> UDPIPEncap(sfc:ip,4,sff,0) -> checklen2;
rewriterChain4[1] -> SetTCPChecksum() -> checklen4;

rewriterChain1OUT[0] -> [0]rewriterChain1IN;
rewriterChain1OUT[1] -> Discard;

rewriterChain2OUT[0] -> [0]rewriterChain2IN;
rewriterChain2OUT[1] -> Discard;
