# ipv6-ndp-exploit

  * [Introduction](#introduction)
  * [Protocols overview](#protocols-overview)
    + [Internet Protocol Version](#internet-protocol-version)
    + [Neighbour Discovery Protocol](#neighbour-discovery-protocol)
    + [Packets' syntax](#packets--syntax)
    + [2.4 Auto configuration process](#24-auto-configuration-process)
    + [2.5 Conceptual Model of a Host](#25-conceptual-model-of-a-host)
  * [3 Attack design](#3-attack-design)
    + [3.1 DOS attack: DAD based](#31-dos-attack--dad-based)
    + [3.2 MiTM attack: Traffic hijacking](#32-mitm-attack--traffic-hijacking)
  * [4 Implementation](#4-implementation)
    + [4.1 Libraries](#41-libraries)
    + [4.2 The DoS attack](#42-the-dos-attack)
    + [4.3 The MiTM attack](#43-the-mitm-attack)
  * [5 Conclusion](#5-conclusion)
- [THC-IPV6-ATTACK-TOOLKIT](#thc-ipv6-attack-toolkit)
- [References](#references)

## Introduction

IPv6 is taking over the internet world, it is now largely deployed within universities, companies, major internet services and government sites. It being the
future of the internet, is due to the larger addressing space, its auto configuration mechanisms and mandatory security. Thanks to IPsec integrity, confidentiality and authentication are guaranteed at layer 3, but this comes after some configuration steps.

The Neighbour Discovery Protocol (NDP) is mandatory to establish those configurations, which make it a very important protocol, and any attacks over it will corrupt the network and its equipments, and makes IPSec useless.

In this study, we are focusing on IPv6 basic security issues mostly related to the Neighbour Discovery Protocol (NDP). Any IPv6 enabled node relies on the NDP for its essential IPv6 operations like auto-address configuration, default router configuration, movement detection in a mobile node case, etc. We are going to study the NDP in detail and then try to figure out possible attacks. This study is a fully engineering case, so it will end up to develop real running attack codes and perform test attacks. We'll design attacks over NDP vulnerabilities, and develop running codes for those attacks.

Note that this study is part of IPv6 Basic Security. Another part of IPv6 Basic Security is about protection of the NDP against various attacks.

## Protocols overview

### Internet Protocol Version

IPv6 (Internet Protocol version 6) is a network connectionless protocol operating over layer 3 of the OSI model (Open Systems Interconnection). IPv6 is the
culmination work done in the IETF in the 1990s to be the successor to IPv4. Its specifications were finalised in RFC 2460[7] in December 1998.

With 128-bit instead of 32-bit addresses, IPv6 has a much more important address space. This considerable amount of addresses allows greater flexibility in the assignment of addresses and a better aggregation of routes in the Internet routing table. The address translation (NAT), which was made popular by the lack of IPv4 addresses is no more necessary. It is still used in some cases though.

IPv6 also has mechanisms for automatic assignment of addresses that facilitates also their renewal. The size of the subnets, variable in IPv4, was set at 64-bit in IPv6. Security through IPsec mechanisms are part of the basis of the Protocol specification. The header of the IPv6 packet has also been simplified.

The deployment of IPv6 on the Internet is complicated due to the incompatibility of IPv4 and IPv6 addresses. Automatic address translators have significant practical problems (RFC 4966[3]). During a transition phase where co-exist IPv6 and IPv4, the hosts have a double stack, meaning that they have both addresses, IPv6 and IPv4, and tunnels to cross the routers' groups which do not yet support IPv6.

In 2011, only a few companies had deployed IPv6 technology on their internal network, Google and Wikipedia especially. In 2012, the deployment of IPv6 was still limited, the proportion of IPv6 Internet users was estimated at 0.5%, and this despite urgent calls to speed up the migration directed to the Internet access providers. In fact the exhaustion of available public IPv4 addresses is imminent.

> Some IPv6 addressing schemes
```
Unspecified ::/
Loopback ::1/
Multicast FF00::/
Link-local unicast FE80::/
Site-local unicast FEC0::/
Global unicast Everything else
```
> Some multicast addresses scope
```
ffx1::/16 local
ffx2::/16 link local
ff02::1 All nodes on the local network segment
ff02::2 All routers on the local network segment
ff02::5 OSPFv3 All SPF routers
ff02::6 OSPFv3 All DR routers
ff02::8 IS-IS for IPv6 routers
ff02::9 RIP routers
```
Another point is the MAC mapping in IPv6, where the Ethernet MAC is derived by the four low-order octets OR'ed with the MAC 33:33:00:00:00:00, so for example the IPv6 address FF02:DEAD:BEEF::1:3 would map to the Ethernet MAC address 33:33:00:01:00:03.

This was for the addressing plan, let us look into the packet format. It has a 320 bit (40 bytes) header, it has 8 fields among which the source and destination addresses, the hop limit (1 byte), which is decremented by each crossed router, the next header (1 byte) indicated the header that encapsulates the IP one, the payload field (2 bytes) indicates the length of the data field transported by the packet (1460 maximum), the flow label (2,5 bytes) is used to label a particular data flow. Finally the version field should indicate 0x6.

### Neighbour Discovery Protocol

Neighbour Discovery (ND) is an IPv6 protocol, based on ICMPv6 messages exchange between nodes. It is built upon five ICMPv6 packet types (Table-3): Router Solicitation (RS), Router Advertisement (RA), Neighbour Solicitation (NS), Neighbour Advertisement (NA), Redirect.

Compared to IPv4, this protocol is a combination of a set of protocol from the TCP/IPv4 family, including ARP and ICMP. Though IPv4 protocol suite doesn't define a process for unreachability detection.

It consists of a mechanism with which a node that has just been added to a network, see the presence of other nodes on the same link, in addition to viewing their IP addresses. This Protocol also deals with keeping clean the caches where is stored the information relating to the context of the network to which a node is connected. It uses ICMPv6 messages, and is the basis to allow IPv6 au to configuration mechanism. It is used for the following purposes in the below syntax.

### Packets' syntax

In this subsection, we'll see the nominal form of a packet and the requirement for it to be validated by a receiving node. RFC 4861[5] details those requirements.

> Some NDP purposes
```
Router discovery hosts can locate routers residing on attached links.
Prefix discovery hosts can discover address prefixes that are on-link for attached links.
Parameter discovery hosts can find link parameters (e.g., MTU).
Address auto configuration stateless configuration of addresses of network interfaces.
Address resolution mapping between IP addresses and link-layer addresses.
Next-hop determination hosts can find next-hop routers for a destination.
Neighbor unreachability detection (NUD) determine that a neighbor is no longer reachable on the link.
Duplicate address detection (DAD) nodes can check whether an address is already in use.
Redirect router can inform a node about better first-hop routers.
```

So for the packets we tend to forge in our experiments, those requirement should be fulfilled, in particular Checksums and packets' lengths.

Router Solicitation message Sent from Hosts soliciting a quick router advertisement. Must have more than 8 bytes length. Router solicitation messages with a multicast address (ff00::/8) as source are automatically dropped by the receivers. Destination address of the IPv6 header that encapsulates a RS, should be a router multicast address (ff02::2) as seen in 2.1.

Router Advertisement message Sent periodically or in response to router solicitations, through an advertising interface. Destination is set to the soliciting node or to nodes multicast address, if not a unicast address it'll be dropped by
the receivers.

The M flag when activated means the addresses are available threw dynamic host configuration process (DHCP6). The O flag designates dynamic host configuration related Options (DNS). MO set to 0b00 means that no DHCP6 information is available.

Neighbor Solicitation message Helps a node resolves a target address while giving him his own link-layer address. Do NUD by unicast. Router Solicitation messages will be discarded if they doesn't respond to the following requirements: The hop-limit field isn't 255 (went through some router), invalid id checksum, ICMP Code field is not 0, ICMP inferior to 8 bits.

Neighbor Advertisement message respond to NS, or propagate other informations quickly (unreliable).

Redirect message sent from a router (could be spoofed by an attacker) to hosts informing of a better first-hop, or that destination host is just a neighbor (target = destination address). Requirements: Sender is a link local address.

Only routers can send redirects, authentication mechanisms exists but are rarely implemented.

Options stack Neighbor Discovery messages can include a number of options. Such options have the following general syntax. A packet with option field length equal to zero, will be discarded automatically.

The draft [4] describes some well known option field issues. For example, NDP options being processed by the OS Kernel, an on-link host can send many NDPes with large options fields, which takes a lot of CPU power, and affect the host
computing capabilities.

Option field may be extended, respecting some conditions. Section 3.6 of this [4] draft gives more details.

### 2.4 Auto configuration process

In addition to the large addressing space, hosts auto-configuration is the main addition to the internet world since IPv4. Auto-configured addressed may be in one of those states in Figure 8: Tentative, Preferred, Deprecated, Valid, Invalid.

A highly useful aspect of IPv6 is its ability to automatically configure itself without the use of a statefull configuration protocol, such as Dynamic Host Configuration Protocol for IPv6 (DHCPv6). By default, an IPv6 host can configure a link-local address for each interface. By using router discovery, a host can also determine the addresses of routers, additional addresses, and other configuration parameters. The Router Advertisement message indicates whether a statefull address configuration protocol should be used.

Address auto configuration can be performed only on multicast-capable interfaces. RFC 2462 describes address auto configuration.

### 2.5 Conceptual Model of a Host

As described in RFC 4861[5], this model describes the possible data structure that nodes will maintain for each of their IPv6 activated interfaces. Neighbor Discovery Process (NDP) is continually concerned by this task.

- Neighbor Cache: A set of entries about individual neighbors to which traffic has been sent recently (equivalent to ARP cache in IPv4)
- Destination Cache: A set of entries about destinations to which traffic has been sent recently
- Prefix List: A list of the prefixes that define a set of addresses that are on-link
- Default Router List: A list of routers to which packets may be sent. The algorithm for selecting a default router favors routers known to be reachable over those whose reachability is suspect.

Neighbor cache is ordered in entries which can be in one of 5 states: INCOMPLETE, REACHABLE, STALE, DELAY, PROBE. Each entry should be REACHABLE so the node will be able to process IPv6 packets from another host.

## 3 Attack design

Two types of exploits could be developed over IPv6 enabled networks, local and remote ones. In this section, common and less common weaknesses are presented. Many types of attacks are possible[fig:10], among which Traffic hijacking or Fabrication, Denial of Service and Performance degrading.

Every mechanism, implicating IPv6, has his DoS type weaknesses defined within its RFC's security considerations section. In this work we'll try to define a more useful fishing attack.

### 3.1 DOS attack: DAD based

This is the simplest attack that could be implemented on a local link, yet its effects are major. To check the uniqueness of unicast and link-local addresses, machines must be running an algorithm called Duplicate address Detection (DAD) before using any new address. The algorithm uses the NS and a NA ICMPv control messages. If an address already in service is discovered, it cannot be assigned to the interface.

- A NA is received: the current address is used as a valid address by another machine. This address is not unique and cannot be accepted.
- A NS message is received (another DAD is currently running); also, the address is a temporary address to another machine, and that address cannot be used by any of the machines.


- Nothing is received by the end of 1 second (default value): the address is unique, it goes from a provisional to a valid state, and it is assigned to the interface.

An attacker who wants to prevent a victim from receiving an IPv6 address, could advertise to any host requesting a NS DAD message. The Figure 11 shows how this attack is performed.

This attack is part of thethctoolkit under the name ./dos-new-ip6[10].

### 3.2 MiTM attack: Traffic hijacking

In a first scenario, a victim attempts to discover routers on its local link via Router Discovery. It sends an ICMPv6 RS message requesting information from the routers on its local link. A legitimate router responds with an ICMPv6 RA for a lifetime x, and a certain priority, that lets the victim know that it is one of the link routers.

In return, host V installs a default route to its routing table that points to that router, which is erased after a period of x time.

If an attacker, manages to install himself on the link, he could attempt to advertise himself as a default router in the routing table of the victim. To do that, there is plenty of ways:

- Could be based on the lifetime of the configuration, which is one option of RA messages.
- Based on link local RA, an attacker could send a spoofed RA message with his address. This type of attack, was covered by Linux security updates.

- Based on Redirect messages, an attacker could make a router consider him as a better router, and thus redirect traffic towards him. Another way is to spoof Redirect messages, if we know the default router of a node.

- Or based on the priority option of the RA message, a fake router could place himself as a high priority router for some multicast group or unicast node, and then receives all the packets.

For the first option and according to RFC 4862[8], that says: ”If the received Valid Lifetime is greater than 2 hours or greater than RemainingLifetime, set the valid lifetime of the corresponding address to the advertised Valid Lifetime” and ”If RemainingLifetime is less than or equal to 2 hours, ignore the Prefix Information option with regards to the valid lifetime, unless the Router Advertisement from which this option was obtained has been authenticated”.

Then an attacker can spoof a new router advertisement to the victim from the legitimate router and set its lifetime to 2 hours. This is a time consuming attack.

The victim will remove the configured default route after 2 hours. The attacker will send then a RA to insert himself as the default router on the victim's routing table.

The option field is described in a previous section (see Packet syntax 2.3).

This is a half man in the middle attack, where an attacker receives only the

traffic that originates on the victim side, he doesn't receive the responses to those requests. An attacker first get this position then spoof DNS responses to redirect the victim to other web pages, in order to perform another type of attacks. He will forward non DNS traffic.

## 4 Implementation

To emulate the designed attacks, we'll be usinggns3(Graphical Network Simulator) (www.gns3.net), an open source network simulator, that combines Dynamips and Virtualboxes to provide accurate simulations. It supports Cisco
1700, 2600, 3600, 3700, and 7200 hardware routers platforms and runs standard IOS images. In addition it is multiplatform.

The network interface configuration will be set to a Generic Driver adapter, controlled by the gns3 environment.

IPv4 will be turned off to delete any possible unwanted traffic, it can't be totally disabled though, as all the TCP/IP protocols depend on it, and as the system uses it (127.0.0.1). The kernel is built with its support. A kernel built without it will see neither of the two addressing protocols working.

The topology I'm using to test the attack, is compound of 3 hosts, a router and a switch. One of the hosts is the Vitim, the other is the Attacker and the third one is the web server the Vitim is trying to reach. All hosts are running a Linux 2.6, with full support of IPv6 through the ”ipv6” kernel module.

The router is a Cisco 3720, with full support of IPv6 and RIPng protocols. I used c3620-j1s3-mz.123-19.image. The emulation with Dynamips requires this

IOS image of the emulated system, that could be found on the internet, or downloaded from cisco.com if any courses are attended at The Cisco Learning Network. Performing some manipulations on the router, pinging and tracerouting went fine. The test lab is ready!

### 4.1 Libraries

UNIX was basically created to be a programming environment. Every peripheral is seen as a file, and interacting with it is reduced to writing/reading operations from this file. Sockets aren't an exception,

To code and test those algorithms, we'll be using the sockets API defined in the rfc2292[9]. The ”sockets” API was developed in the early 80s for TCP/IP version 4, rfc3493[6] describes the changes and extensions in this API to adapt IPv6.

To make the transition from simple IPv4 socketing to IPv6, one should consider the length of the addresses, thus the structure that holds the IPv4 addresses: struct sockaddrin should be replaced by struct sockaddrin6 since the first one only supports 32 bits addresses. AFINET6 address family was defined.

```
struct sockaddrin6{
uchar sin6len;
uchar sin6family;
uint16t sin6port;
uint32t sin6flowinfo;
struct in6addr sin6addr;
};
```
```
socket(PFINET6,SOCKSTREAM,0); /* TCP socket */
socket(PFINET6,SOCKDGRAM,0); /* UDP socket */
```
The IETF had standardized two sets of extensions for the IPv6 socketing, rfc3493 and rfc3542.

- RFC 3493 Basic Socket Interface Extensions for IPv6: Provides standard definitions for Core socket functions, Address data structures, NametoAddresstranslation functions, and Address conversion functions
- RFC 3542 Advanced Sockets Application Program Interface (API) for IPv6: Defines interfaces for accessing special IPv6 packet information such as the IPv6 header and the extension headers.

We'll not focus a lot on those aspects, we'll be using `THC-IPV6` framework to code our proof of concepts. It is an open source library and attack toolkit licensed under `GPLv3`, developped by the thc communitythc.org, for UNIX like OS, because it uses the `procfs^1`.

Its documentation is available online onthc.org/thc-ipv6/READMEand is included in the current report Annex A.

thc-tools The thc-ipv6 toolkit have been around since 2004. The library contains a lot of useful functions we'll be using to develop our attack. The functions are detailed in the Annex I (official documentation) those functions include very useful short cuts to develop a complete solution.

Some functions are aimed to generate and send packets, add headers, get mac addresses from sniffing around, get own mac address, get own IPv6 address, send a packet as fragments, inverse packet to rapidly send a response by switching the sender and receiver's addresses, and many others.

It also include some IP-sec functionality concerning the generation and management of keys. Another functions gives us the simplest way to generate RA messages to advertise oneself over an interface,thcrouteradv6.c.

Current this toolkit is under a lot of limitations, it runs on Linux and Little Endian platforms only, it is also limited to 32-Bit and to the Ethernet. One needs to installssltoolsandpcaptoolsto be able to compile the library.

### 4.2 The DoS attack

THC-IPv6 toolkit comes, in addition to the library, with a set of tools and exploits, ready to use, of the most commonly known ND vulnerabilities.

the DAD attack illustrated in the precedent section is actually illustrated by thedos-new-ip6.cprogram.

To test this program we'll disable the eth0 interface ofarch 1 host, launch the program on theBT5r3machine (attacker), and reactivate the IPv6 on the victime. The mechanism this DOS attack is based upon is decribed on the sections before. Pinging and tracerouting doesn't work anymore.

In fact the globale address isn't configured, and the local address is unresponsive (^1) The /proc file system is a special filesystem in UNIX-like operating systems that presents information about processes and other system information as the host will drop any traffic on that interface. The address is only there to communicate DAD messages, it becomes definitive only if the DAD mechanism succeeds. 

### 4.3 The MiTM attack

Our attack is a Half-MIT based, as described in a previous section, in order for an attacker to get a MIT priveleges, he can do it, as seen before, in many ways. The one we'll be using is the life time based one.

The attack is performed in two phases, first lifetime of the genuine router is set to zero, then the fake router is advertised with a high priority and a large lifetime. This results into making a rogue router attack.

ip -6 routecommand on the victim shows us the current routing table on the default interface, and how it changed to put the attacker as the default gateway.

## 5 Conclusion

In this project we have seen how does the IPv6 protocol manages its autoconfiguration futures, and how the processes implicated in this mechanisms are weak, and sensitive to protocol attacks. We build some attack scenarios over those weaknesses, and we tested them.

IPv6 still not largely deployed is a gold mine for security researchers, it is build to make internet more secure through its basic elements (IPsec, AAA, Firewalls, SEND, ..).

The small hosts density (up to 2^127 host by subnet) makes scanning, worm propagation and other related threats harder. Though its addressing and configuration are complicated, and those complications result in many exploitable weaknesses.


# THC-IPV6-ATTACK-TOOLKIT
(c) 2005-2012 vh@thc.org [http://www.thc.org](http://www.thc.org)

```
Licensed under GPLv3 (see LICENSE !le)
[..]
```


# References

**[1]** RFC 2464.

**[2]** December 2012.

**[3]** E. Davies C. Aoun, Energize Urnet. Reasons to move the network address translator - protocol translator (nat-pt) to historic status.IETF, July 2007.

**[4]** F. Gont. Security assessment of neighbor discovery (nd) for ipv6 draft gont-opsec-ipv6-nd-security-00.IETF, December 2012.

**[5]** E. Nordmark T. Narten H. Soliman, W. Simpson. Neighbor discovery for ip version 6 (ipv6).IETF, September 2007.

**[6]** J. Bound J. McCann W. Stevens R. Gilligan, S. Thomson. Basic socket interface extensions for ipv6.IETF, February 2003.

**[7]** S. Deering R. Hinden. Internet protocol, version 6 (ipv6) specification. IETF, December 1998.

**[8]** S. Thomson T. Jinmei, T. Narten. Ipv6 stateless address autoconfiguration. IETF, September 2007.

**[9]** M. Thomas W. Stevens. Advanced sockets api for ipv6.IETF, February 1998.

**[10]** [http://www.thc.org.THC-IPV6-ATTACK-TOOLKIT](http://www.thc.org.THC-IPV6-ATTACK-TOOLKIT.) [http://www.thc.org](http://www.thc.org,) 2012.
