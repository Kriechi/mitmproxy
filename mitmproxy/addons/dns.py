import copy
import typing
import socket

from dnslib import DNSRecord, RR, QTYPE, RCODE, parse_time
from dnslib.server import DNSServer, BaseResolver, DNSLogger

from mitmproxy import ctx


class CustomResolver(BaseResolver):
    def __init__(self, *, address, port, ttl, replacements, blackhole):
        self.address = address
        self.port = port
        self.ttl = parse_time(ttl)

        self.replacements = []
        for i in replacements:
            for rr in RR.fromZone(i, ttl=self.ttl):
                self.replacements.append((rr.rname, QTYPE[rr.rtype], rr))

        self.blackhole = blackhole

    def resolve(self, request, handler):
        matched = False
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]

        # Try to resolve locally
        for name, rtype, rr in self.replacements:
            if qname.matchGlob(name):
                if qtype in (rtype, 'ANY', 'CNAME'):
                    a = copy.copy(rr)
                    a.rname = qname
                    reply.add_answer(a)
                matched = True

        # Check for NXDOMAIN
        if any([qname.matchGlob(s) for s in self.blackhole]):
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
            return reply

        if matched:
            return reply

        # Otherwise proxy to upstream
        if not reply.rr:
            try:
                proxy_r = request.send(self.address, self.port, timeout=5)
                reply = DNSRecord.parse(proxy_r)
            except socket.timeout:
                reply.header.rcode = getattr(RCODE, 'SERVFAIL')

        return reply

class CustomLogger(DNSLogger):
    def __init__(self):
        super().__init__()

    def log_request(self, handler, request):
        msg = f"DNS Request: [{handler.client_address[0]}:{handler.client_address[1]}] / '{request.q.qname}' ({QTYPE[request.q.qtype]})"
        print(msg)
        self.log_data(request)

    def log_reply(self, handler, reply):
        if reply.header.rcode == RCODE.NOERROR:
            msg = f"DNS Reply: [{handler.client_address[0]}:{handler.client_address[1]}] / '{reply.q.qname}' ({QTYPE[reply.q.qtype]}) / RRs: {','.join([QTYPE[a.rtype] for a in reply.rr])}"
        else:
            msg = f"DNS Reply: [{handler.client_address[0]}:{handler.client_address[1]}] / '{reply.q.qname}' ({QTYPE[reply.q.qtype]}) / {RCODE[reply.header.rcode]}"
        print(msg)
        self.log_data(reply)

    def log_truncated(self, handler, reply):
        msg = f"DNS Truncated Reply: [{handler.client_address[0]}:{handler.client_address[1]}] / '{reply.q.qname}' ({QTYPE[reply.q.qtype]}) / RRs: {','.join([QTYPE[a.rtype] for a in reply.rr])}"
        print(msg)
        self.log_data(reply)

    def log_error(self, handler, error):
        msg = f"DNS Invalid Request: [{handler.client_address[0]}:{handler.client_address[1]}] / {error}"
        print(msg)

    def log_data(self,dnsobj):
        print("\n",dnsobj.toZone("    "),"\n",sep="")


class DNS:
    def __init__(self):
        self.udp_server: DNSServer = None
        self.is_running = False

    def load(self, loader):
        loader.add_option(
            "dns_listen", str, "127.0.0.1:8053",
            "Listen on this host:port for DNS queries.",
        )
        loader.add_option(
            "dns_upstream", str, "8.8.8.8:53",
            "Upstream DNS server to forward DNS requests to.",
        )
        loader.add_option(
            "dns_ttl", str, "60s",
            "TTL for DNS replies.",
        )
        loader.add_option(
            "dns_replace", typing.Sequence[str], [],
            "DNS Zone entries to replace. Format: 'example.com A 1.2.3.4'",
        )
        loader.add_option(
            "dns_blackhole", typing.Sequence[str], [],
            "Names to fail with a NXDOMAIN reply. Format: 'example.com'",
        )

    def running(self):
        self.master = ctx.master
        self.options = ctx.options
        self.is_running = True
        self.configure(["dns"])

    def configure(self, updated):
        if "dns" not in updated:
            return
        if not self.is_running:
            return
        if not self.options.dns_replace and not self.options.dns_blackhole:
            return
        self.refresh_server()

    def refresh_server(self):
        if self.udp_server and self.udp_server.isAlive():
            self.udp_server.stop()

        upstream_host, upstream_port = self.options.dns_upstream.split(":")
        resolver = CustomResolver(
            address=upstream_host,
            port=int(upstream_port),
            ttl=self.options.dns_ttl,
            replacements=self.options.dns_replace,
            blackhole=self.options.dns_blackhole,
        )

        dns_listen_host, dns_listen_port = self.options.dns_listen.split(":")
        self.udp_server = DNSServer(
            resolver=resolver,
            address=dns_listen_host,
            port=int(dns_listen_port),
            logger=CustomLogger()
        )
        self.udp_server.start_thread()

        ctx.log.info(f"DNS server is listening at {dns_listen_host}:{dns_listen_port} with upstream {self.options.dns_upstream}")
        for i in self.options.dns_replace:
            ctx.log.info(f"  Replacing DNS record: {i}")
        for i in self.options.dns_blackhole:
            ctx.log.info(f"  Blackholing DNS name: {i}")
