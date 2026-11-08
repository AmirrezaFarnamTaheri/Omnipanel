package networking

import (
	"errors"
	"testing"
)

func validSnapshot() Snapshot {
	return Snapshot{
		NodeID:                    "node-1",
		Engine:                    "nftables",
		Generation:                1,
		LoopbackAcceptPresent:     true,
		ProtectedSSHPort:          22,
		ProtectedManagementPort:   8443,
		PrivateEgressBlockedCIDRs: append([]string(nil), RequiredPrivateEgressCIDRs...),
		Rules: []Rule{
			{
				RuleID:           "omni-ssh-accept",
				Table:            "inet filter",
				Chain:            "input",
				Direction:        "ingress",
				Protocol:         "tcp",
				PortRange:        "22",
				SourceCIDR:       "0.0.0.0/0",
				DestinationCIDR:  "0.0.0.0/0",
				Verdict:          "accept",
				OwnedByOmniPanel: false,
				ProtectedRule:    true,
			},
			{
				RuleID:           "omni-vless-443",
				Table:            "inet omnipanel",
				Chain:            "input",
				Direction:        "ingress",
				Protocol:         "tcp",
				PortRange:        "443",
				SourceCIDR:       "0.0.0.0/0",
				DestinationCIDR:  "0.0.0.0/0",
				Verdict:          "accept",
				OwnedByOmniPanel: true,
				ProtectedRule:    false,
			},
		},
	}
}

func TestEvaluateInventoryAcceptsProtectedSnapshot(t *testing.T) {
	rep, err := EvaluateInventory(validSnapshot())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rep.SSHManagementProtected || !rep.LoopbackProtected || !rep.PrivateEgressGuardComplete {
		t.Fatalf("expected all safety checks true: %+v", rep)
	}
	if rep.InvokesHostShell {
		t.Fatal("inventory contract must never invoke host shell")
	}
	if rep.OwnedRuleCount != 1 || rep.UnmanagedRuleCount != 1 {
		t.Fatalf("unexpected rule counts: %+v", rep)
	}
}

func TestEvaluateInventoryRefusesSSHBlockAndMissingPrivateCIDR(t *testing.T) {
	s := validSnapshot()
	s.Rules[0].Verdict = "drop"
	if _, err := EvaluateInventory(s); !errors.Is(err, ErrManagementPortBlocked) {
		t.Fatalf("expected ErrManagementPortBlocked, got %v", err)
	}

	s2 := validSnapshot()
	s2.PrivateEgressBlockedCIDRs = s2.PrivateEgressBlockedCIDRs[:3]
	if _, err := EvaluateInventory(s2); !errors.Is(err, ErrPrivateEgressUnblocked) {
		t.Fatalf("expected ErrPrivateEgressUnblocked, got %v", err)
	}
}


func TestEvaluateInventoryMustRequireActualManagementPortAllow(t *testing.T) {
	// A host may keep SSH working while the personal management panel is
	// accidentally locked out. The inventory used to report this healthy
	// merely because it found no explicit management-port DROP rule.
	s := validSnapshot()
	if _, err := EvaluateInventory(s); !errors.Is(err, ErrManagementPortBlocked) {
		t.Fatalf("snapshot without management-port allow must fail closed, got %v", err)
	}
}

func TestEvaluateInventoryAcceptsRestrictedExplicitManagementPortAllow(t *testing.T) {
	// The management interface can be intentionally private; a 0.0.0.0/0
	// source restriction must not be required for its explicit allow rule.
	s := validSnapshot()
	s.Rules = append(s.Rules, Rule{
		RuleID: "protected-private-management", Table: "inet filter",
		Chain: "input", Direction: "ingress", Protocol: "tcp",
		PortRange: "8443", SourceCIDR: "192.0.2.0/24",
		DestinationCIDR: "0.0.0.0/0", Verdict: "accept",
		ProtectedRule: true,
	})
	if _, err := EvaluateInventory(s); err != nil {
		t.Fatalf("private explicit management-port allow was rejected: %v", err)
	}
}
