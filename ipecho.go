package ipecho

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

type ipecho struct {
	Next   plugin.Handler
	Config *config
}

// ServeDNS implements the middleware.Handler interface.
func (p ipecho) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if p.echoIP(w, r) {
		return dns.RcodeSuccess, nil
	}
	return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
}

// Name implements the Handler interface.
func (ipecho) Name() string {
	return "IPEcho"
}

func (p *ipecho) echoIP(w dns.ResponseWriter, r *dns.Msg) bool {
	if len(r.Question) <= 0 {
		return false
	}

	var rrs []dns.RR

	for i := 0; i < len(r.Question); i++ {
		question := r.Question[i]
		if question.Qclass != dns.ClassINET {
			continue
		}

		switch question.Qtype {
		case dns.TypeAAAA:
			for _, record := range p.handleAAAA(question) {
				rrs = append(rrs, record)
			}
		case dns.TypePTR:
			for _, record := range p.handlePTR(question) {
				rrs = append(rrs, record)
			}
		}
	}

	if len(rrs) > 0 {
		if p.Config.Debug {
			log.Printf("[ipecho] Answering with %d rr's\n", len(rrs))
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = rrs
		w.WriteMsg(m)
		return true
	}
	return false
}

func (p *ipecho) handlePTR(question dns.Question) (rrs []dns.RR) {
	if !strings.HasSuffix(question.Name, "ip6.arpa.") {
		log.Printf("not a ip6.arpa PTR query")
		return
	}
	ipv6str := question.Name[:len(question.Name)-9 /* ip6.arpa. */ -1 /* trailing dot */]

	// e.g. ["efef", "feeb"]
	quads := strings.Split(ipv6str, ".")[0:16] // 16*4 quads
	quads[3] = strings.Join(quads[0:4], "")
	quads[2] = strings.Join(quads[4:8], "")
	quads[1] = strings.Join(quads[8:12], "")
	quads[0] = strings.Join(quads[12:16], "")
	quads = quads[0:4]

	// reverse quad contents
	for i := range quads {
		runes := []rune(quads[i])
		for a, b := 0, len(quads[i])-1; a < b; a, b = a+1, b-1 {
			runes[a], runes[b] = runes[b], runes[a]
		}
		quads[i] = string(runes)
	}

	hostname := fmt.Sprintf("%s%s.%s", p.Config.Prefix, strings.Join(quads, ""), p.Config.Zones[0])

	rrs = append(rrs, &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   question.Name,
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    p.Config.TTL,
		},
		Ptr: dns.Fqdn(hostname),
	})

	return
}

func (p *ipecho) handleAAAA(question dns.Question) (rrs []dns.RR) {
	ip := p.parseIP(&question)
	if ip == nil {
		if p.Config.Debug {
			log.Printf("[ipecho] Parsed IP of '%s' is nil\n", question.Name)
		}
		return
	}
	if ip4 := ip.To4(); ip4 == nil {
		if p.Config.Debug {
			log.Printf("[ipecho] Parsed IP of '%s' is an IPv6 address\n", question.Name)
		}
		rrs = append(rrs, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    p.Config.TTL,
			},
			AAAA: ip,
		})
	}
	return rrs
}

func (p *ipecho) parseIP(question *dns.Question) net.IP {
	if p.Config.Debug {
		log.Printf("[ipecho] Query for '%s'", question.Name)
	}

	for _, zone := range p.Config.Zones {
		if !strings.HasSuffix(strings.ToLower(question.Name), zone) {
			continue
		}
		subdomain := question.Name[:len(question.Name)-len(zone)]
		if len(subdomain) <= 0 {
			if p.Config.Debug {
				log.Printf("[ipecho] Query ('%s') has no subdomain\n", question.Name)
			}
			return nil
		}
		subdomain = strings.Trim(subdomain, ".")
		if p.Config.Prefix != "" && !strings.HasPrefix(strings.ToLower(subdomain), p.Config.Prefix) {
			if p.Config.Debug {
				log.Printf("[ipecho] Query ('%s') prefix does not match\n", question.Name)
			}
			return nil
		}
		ipv6nick := subdomain[len(p.Config.Prefix):]
		if len(ipv6nick) != 16 {
			log.Printf("[ipecho] ipv6 nick is longer than expected")
			return nil
		}
		var quads [4]string
		var quad string
		for i := 0; len(ipv6nick) >= 4; i++ {
			quad, ipv6nick = ipv6nick[0:4], ipv6nick[4:]
			log.Println(quad, ipv6nick)
			quads[i] = quad
		}
		ipv6addr := p.Config.Network + ":" + strings.Join(quads[:], ":")
		log.Println(ipv6addr)
		return net.ParseIP(ipv6addr)
	}

	if p.Config.Debug {
		log.Printf("[ipecho] Query ('%s') does not have a matching zone (%s)\n", question.Name, strings.Join(p.Config.Zones, ", "))
	}
	return nil
}
