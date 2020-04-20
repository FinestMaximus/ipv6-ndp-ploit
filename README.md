# ipv6-ndp-exploit

An attacker could either send unsolicited Router Advertisements and/or illegitimately respond to Router Solicitations, advertising a non-existent system as a default router.

As a result, hosts honouring the aforementioned Router Advertisements would use the advertised rogue router as a default router, and as a result their packets would be black-holed.

In order for an attacker to successfully perform this attack, he would need to be attached to the same network link on which the attack is to be launched, or control a node attached to that network link (e.g., compromise such a node). As described in [RFC3756], this vulnerability could be mitigated by preferring existing routers over new ones.

Additionally, layer-2 switches could possibly allow Router Advertisements messages to be sent only from specific ports.

[RFC6104] analyzes the problem of Rogue IPv6 Router Advertisements, and discusses a number of possible solutions. [RFC6105] discusses a specific solution to this problem based on layer-2 filtering, known as 'RA-Guard'. However, as discussed in [I-D.ietf-v6ops-ra-guard-implementation], some popular RA-Guard implementations can be easily circumvented by leveraging IPv6 extension headers.
