package reports

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// NetworkNode represents a node in the network diagram
type NetworkNode struct {
	IP        string
	Hostname  string
	Services  []string
	IsGateway bool
	Subnet    string
}

// NetworkSubnet represents a subnet with its nodes
type NetworkSubnet struct {
	CIDR    string
	Gateway string
	Nodes   []NetworkNode
}

// NetworkDiagram holds the complete network topology
type NetworkDiagram struct {
	Subnets []NetworkSubnet
}

// BuildNetworkDiagram analyzes findings and builds a network topology
func BuildNetworkDiagram(findings []Finding) *NetworkDiagram {
	// Collect all IPs and their info
	nodeMap := make(map[string]*NetworkNode)

	for _, f := range findings {
		for _, host := range f.AffectedHosts {
			// Extract IP from host (might be ip:port or just ip or domain)
			ip := extractIP(host)
			if ip == "" {
				continue
			}

			if _, ok := nodeMap[ip]; !ok {
				nodeMap[ip] = &NetworkNode{
					IP:       ip,
					Services: []string{},
				}
			}

			// Add service info
			if f.Module == "services" && strings.Contains(f.Title, "Service") {
				parts := strings.Split(f.Title, " ")
				if len(parts) > 0 {
					nodeMap[ip].Services = appendUnique(nodeMap[ip].Services, parts[0])
				}
			}

			// Try to extract hostname from domain-based hosts
			if !isIP(host) {
				hostname := extractHostname(host)
				if hostname != "" && nodeMap[ip].Hostname == "" {
					nodeMap[ip].Hostname = hostname
				}
			}
		}
	}

	// Group nodes by subnet
	subnetMap := make(map[string]*NetworkSubnet)

	for ip, node := range nodeMap {
		subnet := guessSubnet(ip)
		if subnet == "" {
			continue
		}

		if _, ok := subnetMap[subnet]; !ok {
			subnetMap[subnet] = &NetworkSubnet{
				CIDR:  subnet,
				Nodes: []NetworkNode{},
			}
		}

		// Check if this could be a gateway (.1 or .0)
		if isLikelyGateway(ip) {
			node.IsGateway = true
			subnetMap[subnet].Gateway = ip
		}

		node.Subnet = subnet
		subnetMap[subnet].Nodes = append(subnetMap[subnet].Nodes, *node)
	}

	// Sort subnets and nodes
	var subnets []NetworkSubnet
	for _, s := range subnetMap {
		sort.Slice(s.Nodes, func(i, j int) bool {
			return compareIPs(s.Nodes[i].IP, s.Nodes[j].IP)
		})
		subnets = append(subnets, *s)
	}

	sort.Slice(subnets, func(i, j int) bool {
		return subnets[i].CIDR < subnets[j].CIDR
	})

	return &NetworkDiagram{Subnets: subnets}
}

// GenerateSVG creates an SVG representation of the network
func (d *NetworkDiagram) GenerateSVG() string {
	if len(d.Subnets) == 0 {
		return ""
	}

	var sb strings.Builder

	// Calculate dimensions
	maxNodesPerSubnet := 0
	for _, s := range d.Subnets {
		if len(s.Nodes) > maxNodesPerSubnet {
			maxNodesPerSubnet = len(s.Nodes)
		}
	}

	nodeWidth := 180
	nodeHeight := 60
	nodeSpacing := 20
	subnetSpacing := 80
	leftMargin := 50
	topMargin := 80

	width := leftMargin*2 + (nodeWidth+nodeSpacing)*maxNodesPerSubnet
	if width < 800 {
		width = 800
	}
	height := topMargin + (nodeHeight+subnetSpacing)*len(d.Subnets) + 100

	// SVG header
	sb.WriteString(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d">
<style>
  .subnet { fill: #f0f4f8; stroke: #4a5568; stroke-width: 2; rx: 10; }
  .subnet-label { font-family: monospace; font-size: 14px; font-weight: bold; fill: #2d3748; }
  .node { fill: #ffffff; stroke: #4a5568; stroke-width: 1; rx: 5; }
  .gateway { fill: #fed7d7; stroke: #c53030; stroke-width: 2; }
  .node-ip { font-family: monospace; font-size: 11px; fill: #2d3748; }
  .node-hostname { font-family: sans-serif; font-size: 10px; fill: #718096; }
  .node-services { font-family: monospace; font-size: 9px; fill: #4299e1; }
  .title { font-family: sans-serif; font-size: 20px; font-weight: bold; fill: #1a202c; }
  .legend { font-family: sans-serif; font-size: 11px; fill: #4a5568; }
</style>
`, width, height, width, height))

	// Title
	sb.WriteString(fmt.Sprintf(`<text x="%d" y="30" class="title">Network Topology Diagram</text>
`, width/2-150))

	// Legend
	sb.WriteString(`<rect x="20" y="45" width="15" height="15" class="node gateway"/>
<text x="40" y="57" class="legend">Gateway</text>
<rect x="120" y="45" width="15" height="15" class="node"/>
<text x="140" y="57" class="legend">Host</text>
`)

	// Draw each subnet
	y := topMargin
	for _, subnet := range d.Subnets {
		nodesWidth := len(subnet.Nodes)*(nodeWidth+nodeSpacing) + nodeSpacing
		if nodesWidth < 300 {
			nodesWidth = 300
		}

		// Subnet box
		sb.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="%d" class="subnet"/>
`, leftMargin-10, y-10, nodesWidth, nodeHeight+40))

		// Subnet label
		sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="subnet-label">%s</text>
`, leftMargin, y+10, subnet.CIDR))

		// Draw nodes
		x := leftMargin + nodeSpacing
		for _, node := range subnet.Nodes {
			nodeClass := "node"
			if node.IsGateway {
				nodeClass = "node gateway"
			}

			sb.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="%d" class="%s"/>
`, x, y+20, nodeWidth, nodeHeight, nodeClass))

			// IP
			sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="node-ip">%s</text>
`, x+5, y+35, node.IP))

			// Hostname (truncated if too long)
			hostname := node.Hostname
			if len(hostname) > 25 {
				hostname = hostname[:22] + "..."
			}
			if hostname != "" {
				sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="node-hostname">%s</text>
`, x+5, y+50, hostname))
			}

			// Services (truncated)
			if len(node.Services) > 0 {
				services := strings.Join(node.Services, ", ")
				if len(services) > 30 {
					services = services[:27] + "..."
				}
				sb.WriteString(fmt.Sprintf(`<text x="%d" y="%d" class="node-services">%s</text>
`, x+5, y+70, services))
			}

			x += nodeWidth + nodeSpacing
		}

		y += nodeHeight + subnetSpacing
	}

	sb.WriteString("</svg>")
	return sb.String()
}

// GenerateASCII creates an ASCII representation of the network
func (d *NetworkDiagram) GenerateASCII() string {
	if len(d.Subnets) == 0 {
		return "No network topology data available\n"
	}

	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                           NETWORK TOPOLOGY DIAGRAM                           ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════════════════════╝\n\n")

	for _, subnet := range d.Subnets {
		// Subnet header
		sb.WriteString(fmt.Sprintf("┌─────────────────────────────────────────────────────────────────────────────┐\n"))
		sb.WriteString(fmt.Sprintf("│ Subnet: %-68s │\n", subnet.CIDR))
		sb.WriteString(fmt.Sprintf("├─────────────────────────────────────────────────────────────────────────────┤\n"))

		// Nodes
		for _, node := range subnet.Nodes {
			gwMark := "   "
			if node.IsGateway {
				gwMark = "[GW]"
			}

			hostname := node.Hostname
			if len(hostname) > 30 {
				hostname = hostname[:27] + "..."
			}
			if hostname == "" {
				hostname = "-"
			}

			services := strings.Join(node.Services, ", ")
			if len(services) > 25 {
				services = services[:22] + "..."
			}
			if services == "" {
				services = "-"
			}

			sb.WriteString(fmt.Sprintf("│ %s %-15s %-30s %-20s │\n", gwMark, node.IP, hostname, services))
		}

		sb.WriteString(fmt.Sprintf("└─────────────────────────────────────────────────────────────────────────────┘\n\n"))
	}

	// Legend
	sb.WriteString("Legend: [GW] = Gateway\n")

	return sb.String()
}

// Helper functions

func extractIP(host string) string {
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		portPart := host[idx+1:]
		// Check if it's actually a port (numeric)
		if _, err := fmt.Sscanf(portPart, "%d", new(int)); err == nil {
			host = host[:idx]
		}
	}

	// Remove protocol
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")

	// Check if it's an IP
	if ip := net.ParseIP(host); ip != nil {
		return host
	}

	// Try to resolve hostname
	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		return ips[0].String()
	}

	return ""
}

func extractHostname(host string) string {
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		portPart := host[idx+1:]
		if _, err := fmt.Sscanf(portPart, "%d", new(int)); err == nil {
			host = host[:idx]
		}
	}

	// Remove protocol
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")

	// Remove trailing slash
	host = strings.TrimSuffix(host, "/")

	if !isIP(host) {
		return host
	}
	return ""
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

func guessSubnet(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	// For IPv4, assume /24 subnet
	if parsed.To4() != nil {
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		}
	}

	return ""
}

func isLikelyGateway(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	lastOctet := parts[3]
	return lastOctet == "1" || lastOctet == "0" || lastOctet == "254"
}

func compareIPs(a, b string) bool {
	aIP := net.ParseIP(a)
	bIP := net.ParseIP(b)
	if aIP == nil || bIP == nil {
		return a < b
	}

	aBytes := aIP.To4()
	bBytes := bIP.To4()
	if aBytes == nil || bBytes == nil {
		return a < b
	}

	for i := 0; i < 4; i++ {
		if aBytes[i] != bBytes[i] {
			return aBytes[i] < bBytes[i]
		}
	}
	return false
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
