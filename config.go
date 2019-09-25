package ipecho

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/plugin"
)

type config struct {
	// Zones defines the zones we will react to
	Zones []string
	// Network to return AAAA records for
	Network string
	network *net.IPNet

	// Prefix to match for
	Prefix string
	// TTL to use for response
	TTL uint32
	// Debug mode
	Debug bool
}

func parse(c *caddy.Controller) (*config, error) {
	config := config{
		TTL: 2629800,
	}

	for c.Next() {
		zones := c.RemainingArgs()
		config.Zones = zones
		if len(zones) == 0 {
			config.Zones = make([]string, len(c.ServerBlockKeys))
		}
		for i, str := range config.Zones {
			config.Zones[i] = plugin.Host(str).Normalize()
		}
		for c.NextBlock() {
			switch c.Val() {
			case "network":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return nil, c.ArgErr()
				}
				_, net, err := net.ParseCIDR(args[0])
				if err != nil {
					return nil, err
				}
				if net == nil {
					return nil, c.Err("invalid network")
				}
				config.network = net
				if bits, _ := net.Mask.Size(); bits > 64 {
					log.Println("bitlen is", bits)
					return nil, c.Err("network is smaller than /64")
				}
				if args[0] != config.network.String() {
					return nil, c.Err("invalid network")
				}
				config.Network = args[0][:strings.Index(args[0], "/")]
			case "ttl":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return nil, c.ArgErr()
				}
				ttl, err := strconv.ParseUint(args[0], 10, 32)
				if err != nil {
					return nil, err
				}
				config.TTL = uint32(ttl)
			case "prefix":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				prefix := args[0]
				config.Prefix = prefix
			case "debug":
				config.Debug = true
			}
		}
	}
	if config.Debug {
		log.Println("[ipecho] Debug Mode is on")
		log.Printf("[ipecho] Parsed %d zones: %s\n", len(config.Zones), strings.Join(config.Zones, ", "))
		log.Printf("[ipecho] TTL is %d", config.TTL)
	}
	if len(config.Zones) <= 0 {
		return nil, fmt.Errorf("There is no domain to handle")
	}
	if config.Network == "" {
		return nil, fmt.Errorf("missing network specification")
	}
	return &config, nil
}
