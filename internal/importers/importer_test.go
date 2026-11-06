package importers

import "testing"

func TestEvaluateDryRunMarksCountersNonBillableAndRejectsUnsupportedPaths(t *testing.T) {
	res, err := EvaluateDryRun(ExportBundle{
		SourcePanel:   "3x-ui",
		SourceVersion: "2.4.0",
		Inbounds: []SourceInbound{
			{
				Tag:        "vless-ok",
				Protocol:   "vless-reality-vision",
				Transport:  "tcp",
				Runtime:    "xray",
				ListenPort: 443,
				Clients: []SourceClient{
					{ID: "u1", Email: "alice@example.com", Enable: true, UpBytes: 1024, DownBytes: 2048},
				},
			},
			{
				Tag:        "xray-hy2-bad",
				Protocol:   "hysteria2",
				Transport:  "udp",
				Runtime:    "xray",
				ListenPort: 8443,
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.AdmittedInboundTags) != 1 || len(res.RejectedInboundTags) != 1 {
		t.Fatalf("unexpected admission split: %+v", res)
	}
	if len(res.HistoricalCounters) != 1 || res.HistoricalCounters[0].AccountingClassification != "historical_non_billable" {
		t.Fatalf("expected historical_non_billable classification, got %+v", res.HistoricalCounters)
	}
}
