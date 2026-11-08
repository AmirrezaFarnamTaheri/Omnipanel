package networking

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var (
	ErrInvalidFirewallSnapshot = errors.New("networking: invalid firewall inventory snapshot")
	ErrManagementPortBlocked   = errors.New("networking: protected SSH or management port is not safely accepted")
	ErrLoopbackNotProtected    = errors.New("networking: loopback accept rule is missing")
	ErrPrivateEgressUnblocked  = errors.New("networking: required private/metadata egress CIDR guard is incomplete")
)

var RequiredPrivateEgressCIDRs = []string{
	"10.0.0.0/8",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

type Rule struct {
	RuleID           string `json:"ruleId"`
	Table            string `json:"table"`
	Chain            string `json:"chain"`
	Direction        string `json:"direction"`
	Protocol         string `json:"protocol"`
	PortRange        string `json:"portRange"`
	SourceCIDR       string `json:"sourceCidr"`
	DestinationCIDR  string `json:"destinationCidr"`
	Verdict          string `json:"verdict"`
	OwnedByOmniPanel bool   `json:"ownedByOmniPanel"`
	ProtectedRule    bool   `json:"protectedRule"`
}

type Snapshot struct {
	NodeID                    string   `json:"nodeId"`
	Engine                    string   `json:"engine"`
	Generation                uint64   `json:"generation"`
	LoopbackAcceptPresent     bool     `json:"loopbackAcceptPresent"`
	ProtectedSSHPort          uint16   `json:"protectedSshPort"`
	ProtectedManagementPort   uint16   `json:"protectedManagementPort"`
	PrivateEgressBlockedCIDRs []string `json:"privateEgressBlockedCidrs"`
	Rules                     []Rule   `json:"rules"`
}

type SafetyReport struct {
	InventoryDigest               string
	OwnedRuleCount                int
	UnmanagedRuleCount            int
	SSHManagementProtected        bool
	LoopbackProtected             bool
	PrivateEgressGuardComplete    bool
	RequiresCommitConfirmWatchdog bool
	InvokesHostShell              bool
}

func EvaluateInventory(s Snapshot) (SafetyReport, error) {
	if strings.TrimSpace(s.NodeID) == "" || s.Generation == 0 || s.ProtectedSSHPort == 0 || s.ProtectedManagementPort == 0 {
		return SafetyReport{}, ErrInvalidFirewallSnapshot
	}
	switch s.Engine {
	case "nftables", "iptables", "ufw", "firewalld":
	default:
		return SafetyReport{}, fmt.Errorf("%w: unsupported engine %q", ErrInvalidFirewallSnapshot, s.Engine)
	}
	if !s.LoopbackAcceptPresent {
		return SafetyReport{}, ErrLoopbackNotProtected
	}

	seen := make(map[string]struct{}, len(s.Rules))
	var owned, unmanaged int
	var sshAccept, sshBlockedBeforeAccept, mgmtAccept, mgmtBlockedBeforeAccept bool

	for _, r := range s.Rules {
		if strings.TrimSpace(r.RuleID) == "" {
			return SafetyReport{}, ErrInvalidFirewallSnapshot
		}
		if _, dup := seen[r.RuleID]; dup {
			return SafetyReport{}, fmt.Errorf("%w: duplicate ruleId %q", ErrInvalidFirewallSnapshot, r.RuleID)
		}
		seen[r.RuleID] = struct{}{}
		if r.OwnedByOmniPanel {
			owned++
		} else {
			unmanaged++
		}
		if r.Direction == "ingress" && (r.Protocol == "tcp" || r.Protocol == "any") {
			if portInRange(int(s.ProtectedSSHPort), r.PortRange) {
				if r.Verdict == "accept" && r.SourceCIDR == "0.0.0.0/0" {
					sshAccept = true
				} else if (r.Verdict == "drop" || r.Verdict == "reject") && !sshAccept {
					sshBlockedBeforeAccept = true
				}
			}
			if portInRange(int(s.ProtectedManagementPort), r.PortRange) {
				if r.Verdict == "accept" {
					mgmtAccept = true
				} else if (r.Verdict == "drop" || r.Verdict == "reject") && !mgmtAccept {
					mgmtBlockedBeforeAccept = true
				}
			}
		}
	}

	if !sshAccept || !mgmtAccept || sshBlockedBeforeAccept || mgmtBlockedBeforeAccept {
		return SafetyReport{}, ErrManagementPortBlocked
	}

	blocked := make(map[string]struct{}, len(s.PrivateEgressBlockedCIDRs))
	for _, c := range s.PrivateEgressBlockedCIDRs {
		blocked[c] = struct{}{}
	}
	for _, req := range RequiredPrivateEgressCIDRs {
		if _, ok := blocked[req]; !ok {
			return SafetyReport{}, fmt.Errorf("%w: missing %s", ErrPrivateEgressUnblocked, req)
		}
	}

	cidrs := append([]string(nil), s.PrivateEgressBlockedCIDRs...)
	sort.Strings(cidrs)
	canonicalBytes, err := json.Marshal(struct {
		NodeID     string   `json:"nodeId"`
		Engine     string   `json:"engine"`
		Generation uint64   `json:"generation"`
		CIDRs      []string `json:"cidrs"`
		Rules      []Rule   `json:"rules"`
	}{
		NodeID:     s.NodeID,
		Engine:     s.Engine,
		Generation: s.Generation,
		CIDRs:      cidrs,
		Rules:      s.Rules,
	})
	if err != nil {
		return SafetyReport{}, err
	}
	sum := sha256.Sum256(canonicalBytes)

	return SafetyReport{
		InventoryDigest:               hex.EncodeToString(sum[:]),
		OwnedRuleCount:                owned,
		UnmanagedRuleCount:            unmanaged,
		SSHManagementProtected:        true,
		LoopbackProtected:             true,
		PrivateEgressGuardComplete:    true,
		RequiresCommitConfirmWatchdog: true,
		InvokesHostShell:              false,
	}, nil
}

func portInRange(port int, spec string) bool {
	if spec == "" || spec == "any" || spec == "*" {
		return true
	}
	if !strings.Contains(spec, "-") {
		v, err := strconv.Atoi(spec)
		return err == nil && v == port
	}
	parts := strings.SplitN(spec, "-", 2)
	lo, err1 := strconv.Atoi(parts[0])
	hi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return port >= lo && port <= hi
}
