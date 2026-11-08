package singbox

import (
	"context"
	"os"
	"testing"
)

// Sing-box's native syntax checker has accepted an unresolved route.final
// reference in the pinned build. Stage must reject it independently, rather
// than return a receipt for a candidate with no resolvable final outbound.
func TestNativeStagerRejectsDanglingAndAmbiguousRouteReferences(t *testing.T) {
	stager, _, stageDir, _ := nativeFixture(t, passingNative)
	cases := []struct {
		name string
		json string
	}{
		{
			name: "unresolved final outbound",
			json: `{"inbounds":[],"outbounds":[{"type":"block","tag":"omni-block"}],"route":{"final":"missing-outbound"}}`,
		},
		{
			name: "duplicate outbound tags",
			json: `{"inbounds":[],"outbounds":[{"type":"block","tag":"block"},{"type":"direct","tag":"block"}],"route":{"final":"block"}}`,
		},
		{
			name: "untagged outbound",
			json: `{"inbounds":[],"outbounds":[{"type":"block"}],"route":{"final":"block"}}`,
		},
		{
			name: "nonstring outbound tag",
			json: `{"inbounds":[],"outbounds":[{"type":"block","tag":42}],"route":{"final":"block"}}`,
		},
		{
			name: "unresolved dns final",
			json: `{"inbounds":[],"outbounds":[{"type":"block","tag":"block"}],"route":{"final":"block"},"dns":{"servers":[{"type":"local","tag":"dns"}],"final":"missing-dns"}}`,
		},
		{
			name: "duplicate dns server tags",
			json: `{"inbounds":[],"outbounds":[{"type":"block","tag":"block"}],"route":{"final":"block"},"dns":{"servers":[{"type":"local","tag":"dns"},{"type":"local","tag":"dns"}],"final":"dns"}}`,
		},
		{
			name: "unresolved default domain resolver",
			json: `{"inbounds":[],"outbounds":[{"type":"block","tag":"block"}],"route":{"final":"block","default_domain_resolver":"missing-dns"},"dns":{"servers":[{"type":"local","tag":"dns"}],"final":"dns"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			receipt, err := stager.Stage(context.Background(), nativeArtifact(tc.json))
			if err == nil || receipt.Path != "" {
				t.Fatalf("unresolved or ambiguous native reference was staged: %+v, %v", receipt, err)
			}
		})
	}
	files, err := os.ReadDir(stageDir)
	if err != nil || len(files) != 0 {
		t.Fatalf("rejected references must leave no staged candidates: %v %v", files, err)
	}
}

func TestNativeStagerAcceptsConsistentOutboundAndDNSTags(t *testing.T) {
	stager, _, _, _ := nativeFixture(t, passingNative)
	content := `{"inbounds":[],"outbounds":[{"type":"block","tag":"omni-block"},{"type":"direct","tag":"omni-public"}],"route":{"final":"omni-public","default_domain_resolver":"omni-dns"},"dns":{"servers":[{"type":"local","tag":"omni-dns"}],"final":"omni-dns"}}`
	receipt, err := stager.Stage(context.Background(), nativeArtifact(content))
	if err != nil || receipt.Path == "" {
		t.Fatalf("consistent explicit references were refused: %+v, %v", receipt, err)
	}
}
