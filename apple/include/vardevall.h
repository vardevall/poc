/* C interface between the Swift apps and the Rust engine. */

#ifndef VARDEVALL_H
#define VARDEVALL_H

#include <stddef.h>
#include <stdint.h>

typedef struct VvHandle VvHandle;

/*
 * IP packets for the tunnel to write, in order, in one call (NEPacketTunnelFlow.writePackets):
 * packets[i] points to lens[i] bytes, for i < n. n is at least 1. The arrays and
 * the buffers are call-scoped. The first nibble of a packet is its version, 6 or 4: IPv4 packets
 * come from the exit in use, to the IPv4 address it gave this node.
 */
typedef void (*vv_packets_cb)(void *ctx, const uint8_t *const *packets, const size_t *lens, size_t n);

/*
 * A JSON event; String is call-scoped. Every event, and so every view, carries "network":"<name>",
 * the name of the network it belongs to ("vardevall" for vv_start). In the list below the member is
 * left out. One of:
 *   {"type":"status","state":"started","listen_port":N}
 *   {"type":"status","state":"stopped"}
 *   Peer events carry the peer fields "key":"<base32 node key>","addr":"<overlay ula>","name":"…"|null.
 *   {"type":"added",<peer fields>,"trust":"key"|"member"}: a configured peer, or one found by
 *     member trust.
 *   {"type":"removed",<peer fields>}: the peer was removed or evicted.
 *   {"type":"peer",<peer fields>,"state":"idle"|"connecting"|"up"|"down"}: the link; once per change.
 *     "up" adds "initiator":bool, "down" adds "reason":"idle"|"unreachable"
 *   {"type":"route",<peer fields>,"route":R|null}: where the peer's data goes; null while the link
 *     is not up. R is {"kind":K,…} as in the view, without "metered" and "degraded".
 *   {"type":"exit","site":"it/home","via":"<base32 node key>"|null,"addr":"<ipv6>",
 *    "ipv4":"<ipv4>"|null}: the exit chosen for a site of this network changed; null
 *     once the site has no live exit. "site" is a country code and an optional name, "it" or
 *     "it/home". "addr" is this node's address in the site and "ipv4" the address in 198.18.0.0/15
 *     the exit gave this node, null when it carries no IPv4; the host configures
 *     both on the tunnel to use that exit. Reported once per change, after the "peer" and "route"
 *     events of the same change.
 *   {"type":"exits","offers":[{"key":"<base32 node key>","site":"it/home"},…]}: the exits this
 *     network remembers, live or not, changed; the host keeps the last one across
 *     restarts and gives it back with vv_remember_exits.
 *   {"type":"switch","address":"host:port","auth":"pinned"|"web",
 *    "state":"connecting"|"registered"|"disconnected", …}
 *     auth is "pinned" for an address known by its key and "web" for a web address (vv-04 §2.1);
 *     "disconnected" adds "reason":"unreachable"|"untrusted"|"token_rejected"|"rejected"|
 *     "rate_limited"|"replaced"|"protocol"
 *   {"type":"budget","transport":"udp"|"turn"|"host:port","total":N,"remaining":N,
 *    "source":"switch"|"turn","level":"plenty"|"half"|"low"|"exhausted"}: the volume a transport may
 *     still carry crossed into a lower level or ran out; an exhausted transport carries nothing
 *     until a fresh budget arrives. Set or removed: {"type":"budget","transport":…,"budget":null}
 *     (a new budget is reported in full).
 *   {"type":"view","local":{…},"peers":[…],"sites":[…],"exit":…}: what the node believes about its
 *     paths, inferred locally; sent at most every 250 ms and only when it changed; a change in meters or
 *     remaining budgets alone is sent at most every 10 s. Each event replaces the last.
 *     local: {"ipv6":NAT,"ipv4":NAT,
 *             "relay":{"addr":"ip:port","server":"ip:port","transport":"udp"|"tls"}|null,
 *             "switches":[{"index":N,"address":"host:port","auth":"pinned"|"web","state":…,"reason":…,
 *                          "transport":"http3"|"http2"|"http1"|null,"retry_in_ms":N|null}],
 *             "transports":[{"name":…,"usable":bool,"meter":{"sent":N,"received":N},
 *                            "budget":{"total":N,"remaining":N,"source":…,"level":…}|null}]}
 *       A switch's retry_in_ms, while it is disconnected, is the time from the event to the next
 *       attempt.
 *       NAT: {"nat":"unknown"|"symmetric"|"udp_blocked"} or {"nat":"punchable","addr":"ip:port"}
 *     peer: {"key":…,"addr":…,"name":…|null,"state":"idle"|"connecting"|"up"|"down",
 *            "route":{"kind":K,"metered":bool,"degraded":bool,…}|null,"nat":"unknown"|"punchable"|"relay_only",
 *            "candidates":[{"kind":"local"|"lan"|"ble"|"static"|"punch"|"relay","addr":…,
 *                           "local":bool,"metered":bool}],
 *            "switches":[N,…],"probing":bool,"fallback":bool,
 *            "meter":{"sent":N,"received":N}|null (the active route's),
 *            "rtt_ms":N|null (the active route's smoothed round trip, to the millisecond),
 *            "routes":[{"kind":K,…,"status":"dormant"|"candidate"|"verified"|"suspect"|"failed",
 *                       "rtt_ms":N|null,"active":bool,"metered":bool,
 *                       "retry_in_ms":N|null,"forget_in_ms":N|null}]}
 *       routes lists every route of the link in rank order, empty while the link is not up; K and
 *       its members are as in "route". It is the trace of the paths the node knows. rtt_ms alone
 *       changing is sent at most every 10 s, like meters. A failed route has retry_in_ms, the time
 *       to its next ping, while it could still carry data, or forget_in_ms, the time until it is
 *       dropped, if it was learned from the peer's frames; both count from the
 *       event.
 *       K: "lan", "internet", "peer_relay" (the peer's TURN address), "own_relay" (through
 *       this node's allocation) with "addr"; "switch" with "switch":N. metered is true for the
 *       relays and the switch. nat is inferred from the peer's shared candidates.
 *     sites: the sites some peer has offered, live or not, [{"site":"it/home","peers":["<key>",…],
 *            "down":["<key>",…],"chosen":"<key>"|null,"addr":"<this node's address in the site>"}];
 *            peers are the live exits of the site, down the ones whose link is down (their last
 *            offer is remembered); chosen is null while none is live.
 *       A site that two exits name differently but that share a prefix is left out.
 *     exit: {"site":"it/home","via":"<key>"} when the host makes this network carry the exit and a
 *       site is in use, else null; with several sites and none picked it is null.
 *   {"type":"log","level":"debug"|"info"|"warn"|"error","message":"…"}
 */
typedef void (*vv_event_cb)(void *ctx, const char *json);

/*
 * A JSON mDNS request for the Bonjour backend (vv-09):
 *   {"op":"register","instance":"…","type":"_vardevall._udp","port":N,"txt":{"k":"v",…}}
 *   {"op":"unregister","instance":"…"}
 *   {"op":"browse"} / {"op":"stop_browse"}
 * String is call-scoped. May be NULL in vv_start: the engine then runs its own mDNS sockets.
 */
typedef void (*vv_mdns_cb)(void *ctx, const char *json);

/*
 * Starts the engine. config_toml is an interface file (vv-07 §3); the default overlay domain is
 * "vardevall.internal". Returns NULL on failure and sets *err_out to a message freed with
 * vv_string_free. This is vv_start_networks with the one network "vardevall".
 *
 * Threading: the engine runs on one thread of its own. All callbacks run on that thread, one at
 * a time, never concurrently with each other, whatever the number of networks. The other
 * functions may be called from any thread. Packets and events keep the order in which they came
 * up, across networks: before an event, on_packets receives the packets that preceded it. DNS
 * queries to a node's own overlay address that arrive through vv_packets_in are answered by the
 * engine itself, with the answer delivered through on_packets.
 *
 * With on_mdns NULL the engine runs its own mDNS sockets and skips the interface that holds the
 * (first) node's overlay address, so the tunnel interface must be configured before vv_start.
 */
VvHandle *vv_start(const char *config_toml, vv_packets_cb on_packets, vv_event_cb on_event,
                   vv_mdns_cb on_mdns, void *ctx, char **err_out);

/*
 * Starts the engine for n networks (1 to 8) in the one tunnel; names[i] and configs[i] are the
 * name and the interface file of network i. A name is a DNS label of at most 51 characters,
 * unique in the set; it is the network's interface name, so its default overlay domain is
 * "<name>.internal", and it is the "network" of its events. The networks share the thread and the
 * callbacks and nothing else: each has its own key, sockets, router and resolver. Two networks
 * with the same network secret are refused. The first network is the default one wherever a
 * network may be NULL.
 *
 * vv_packets_in sends a packet to the network whose /48 holds its destination, and to the first
 * network if none does. The resolver address is the first network's ula: a query to it is
 * answered by the network whose domain or reverse zone holds the name, else by the first
 * network. mDNS requests are combined: on_mdns gets the first "browse", the last "stop_browse"
 * and every "register" and "unregister". The threading rules of vv_start apply. Returns NULL on
 * failure and sets *err_out.
 */
VvHandle *vv_start_networks(const char *const *names, const char *const *configs, size_t n,
                            vv_packets_cb on_packets, vv_event_cb on_event, vv_mdns_cb on_mdns,
                            void *ctx, char **err_out);

/*
 * Stops the engine; no callback runs after it returns, and the handle is freed. May be called from
 * any thread. From another thread it blocks for up to 500 ms while the engine withdraws its mDNS
 * announcements (the unregister and stop_browse requests are delivered before it returns). It may
 * also be called from inside a callback: later callbacks are suppressed and the call does not
 * wait, so the mDNS withdrawals are not delivered. No other function may be called with the handle
 * during or after vv_stop.
 */
void vv_stop(VvHandle *handle);

/*
 * IP packets read from the tunnel (NEPacketTunnelFlow.readPackets), in order, IPv6 or IPv4 as the
 * first nibble says: packets[i] points to lens[i] bytes, for i < n. The arrays and the buffers are call-scoped and read before the call
 * returns. A NULL handle, a NULL array with n > 0, n = 0 and a NULL entry (that packet only) are
 * ignored.
 */
void vv_packets_in(VvHandle *handle, const uint8_t *const *packets, const size_t *lens, size_t n);

/*
 * The set of usable local paths changed (NWPathMonitor); vv-05 §4.6. json may be NULL, or carry
 * which interfaces the platform marks as expensive or constrained (vv-05 §2.2); every member is
 * optional:
 *   {"changed":bool,"metered":bool,"interfaces":[{"name":"pdp_ip0","metered":true},…],
 *    "families":["v4","v6"]}
 * "changed" defaults to true; false only records the metered flags, without a path change.
 * "families" names the address families whose addresses changed and defaults to both.
 * "metered" applies to the interface in use; "interfaces" applies per name and is
 * currently ignored (the engine has one socket).
 */
void vv_path_changed(VvHandle *handle, const char *json);

/*
 * Services are per network; network is the network's name, or NULL for the first.
 *
 * Announces a service to the peers of the network (vve-14 §2.1), replacing one of the same name
 * and transport; the [[service]] entries of the config are announced from the start. name is a
 * DNS label, port is not 0, proto is "tcp" or "udp". Returns 0, or -1 and sets *err_out (also
 * for a network that does not exist).
 */
int vv_announce(VvHandle *handle, const char *network, const char *name, uint16_t port,
                const char *proto, char **err_out);

/*
 * Withdraws every service of that name in the network. Returns 1 if there was one, 0 otherwise
 * (also for a network that does not exist).
 */
int vv_withdraw(VvHandle *handle, const char *network, const char *name);

/*
 * The providers of service name among the peers of the network (vve-14 §3), in the order of the
 * resolver's answers, as JSON: [{"key":"<base32 node key>","addr":"<overlay ula>","name":"…"|null,
 * "port":N,"proto":"tcp"|"udp","live":bool},…]. Returns NULL on failure and sets *err_out.
 */
char *vv_providers(VvHandle *handle, const char *network, const char *name, char **err_out);

/*
 * Chooses which network carries the host's traffic outside the overlay; the choice is
 * the host's runtime state, never a config key. network is the name of a network of the engine, or
 * NULL to turn the exit off (site is then ignored). site is NULL for the network's only site
 * or a site such as "it/home". At most one network carries the exit: choosing one
 * ends the use of another. While an exit is in use the engine keeps the exits of the site
 * connected, and packets read through vv_packets_in whose destination is outside every overlay go
 * to the exit chosen for the site, announced by the "exit" events; while there is none they are
 * dropped. Returns 0, or -1 and sets *err_out (for a network that does not exist or a site that
 * does not parse).
 */
int vv_set_exit(VvHandle *handle, const char *network, const char *site, char **err_out);

/*
 * Gives a network back the offers of its last "exits" event from an earlier run, so
 * that a use of an exit reaches those peers first instead of every peer held by key. network is
 * the name of a network of the engine, or NULL for the first; json is the "offers" array. Call it
 * after the start and before vv_set_exit. Returns 0, or -1 and sets *err_out (for a network that
 * does not exist or JSON that does not parse).
 */
int vv_remember_exits(VvHandle *handle, const char *network, const char *json, char **err_out);

/*
 * The exit in use, as JSON: the string "null" while the host chose none (vv_set_exit)
 * or the site in use has no live exit, else
 *   {"network":"home","site":"it/home","via":"<base32 node key>","addr":"<ipv6>","ipv4":"<ipv4>"|null}
 * "addr" and "ipv4" are this node's addresses in the site and from the exit, the ones the host
 * configures on the tunnel, as in the "exit" event. The DNS servers stay the resolver address of vv_tunnel_settings_networks: the
 * engine answers it and relays the names outside every overlay domain to the exit.
 * Unlike the "exit" events, which report the choice per site whether or not it is used, this says
 * what is in use now; read it after vv_set_exit and on the "exit" and "view" events. Returns NULL on
 * failure and sets *err_out.
 */
char *vv_exit_in_use(VvHandle *handle, char **err_out);

/*
 * A Bonjour browse result, as JSON; every network gets it and ignores one that is not its own:
 *   {"op":"found","instance":"…","txt":{…},"port":N,"addrs":["ip",…],"ifindex":N}
 *   {"op":"lost","instance":"…"}
 */
void vv_mdns_event(VvHandle *handle, const char *json);

/*
 * Tunnel settings for a config, as JSON, without starting the engine:
 *   {"addrs":[{"addr":"…","prefix":N},…],"routes":[{"addr":"…","prefix":N},…],"mtu":N,
 *    "dns":{"servers":["…"],"match_domains":["…"]}}
 * addrs holds the overlay ula/64 and the link-local address; a platform that rejects link-local
 * addresses skips the latter. routes holds the prefixes to route into the tunnel (the overlay
 * ula/64).
 * Returns NULL on failure and sets *err_out.
 */
char *vv_tunnel_settings(const char *config_toml, char **err_out);

/*
 * The settings of n networks (names and configs as in vv_start_networks) in one tunnel, as JSON
 * of the same form: addrs and routes hold every network's, in the order of the networks; mtu is
 * the smallest; dns.servers holds the first network's ula, the one resolver address; and
 * match_domains holds every network's domain and reverse zone. Without starting the engine.
 * Returns NULL on failure and sets *err_out.
 */
char *vv_tunnel_settings_networks(const char *const *names, const char *const *configs, size_t n,
                                  char **err_out);

/*
 * Key and config helpers for the app UI; all return NULL on failure and set *err_out.
 * vv_validate_config returns the summary of the config without secrets: interface, public_key,
 * network_id, name, addrs, listen_port, mtu, domain, accept_members, mdns, fallback_delay_ms,
 * switches ([{"address":"host:port","auth":"pinned"|"web"},…], as the "switch" event names them),
 * turn_servers, stun_servers, services ([{"name","port","proto"},…]), peers,
 * forward (whether the file names upstream resolvers, in which case an exit in use does not
 * receive the host's DNS), exit (the site of the [exit] table, "it/home", or
 * null) and ipv4_home (the IPv4 address an exit gives this node when it is free, which the host
 * can configure while it waits for the "exit" event).
 * vv_start, vv_tunnel_settings and vv_validate_config fail for a key whose interface identifier
 * is reserved (vv-06 §2.2).
 */
char *vv_generate_node_key(char **err_out);                       /* base32 secret (vv-01 §3.2) */
char *vv_generate_network_secret(char **err_out);                 /* base32 network secret */
char *vv_public_key(const char *secret, char **err_out);          /* base32 public key */
char *vv_validate_config(const char *config_toml, char **err_out); /* JSON summary of the config */

void vv_string_free(char *s);

#endif
