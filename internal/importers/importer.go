package importers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

var (
	ErrUnsupportedSourcePanel = errors.New("importers: unsupported source panel")
)

type SourceClient struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	Enable     bool   `json:"enable"`
	UpBytes    uint64 `json:"upBytes"`
	DownBytes  uint64 `json:"downBytes"`
	TotalBytes uint64 `json:"totalBytes"`
}

type SourceInbound struct {
	Tag        string         `json:"tag"`
	Protocol   string         `json:"protocol"`
	Transport  string         `json:"transport"`
	Runtime    string         `json:"runtime"`
	ListenPort uint16         `json:"listenPort"`
	Clients    []SourceClient `json:"clients"`
}

type ExportBundle struct {
	SourcePanel   string          `json:"sourcePanel"`
	SourceVersion string          `json:"sourceVersion"`
	Inbounds      []SourceInbound `json:"inbounds"`
}

type HistoricalCounter struct {
	LogicalUser              string `json:"logicalUser"`
	UpBytes                  uint64 `json:"upBytes"`
	DownBytes                uint64 `json:"downBytes"`
	AccountingClassification string `json:"accountingClassification"`
}

type DryRunResult struct {
	Mode                     string              `json:"mode"`
	JournalDigest            string              `json:"journalDigest"`
	AdmittedInboundTags      []string            `json:"admittedInboundTags"`
	RejectedInboundTags      []string            `json:"rejectedInboundTags"`
	HistoricalCounters       []HistoricalCounter `json:"historicalCounters"`
	RequiresOperatorApproval bool                `json:"requiresOperatorApproval"`
}

func EvaluateDryRun(b ExportBundle) (DryRunResult, error) {
	if (b.SourcePanel != "s-ui" && b.SourcePanel != "3x-ui") || strings.TrimSpace(b.SourceVersion) == "" {
		return DryRunResult{}, ErrUnsupportedSourcePanel
	}
	var admitted, rejected []string
	var counters []HistoricalCounter
	ports := make(map[uint16]struct{})

	for _, ib := range b.Inbounds {
		if ib.ListenPort == 0 {
			rejected = append(rejected, ib.Tag)
			continue
		}
		if _, collision := ports[ib.ListenPort]; collision {
			rejected = append(rejected, ib.Tag)
			continue
		}
		supported := (ib.Protocol == "vless-reality-vision" && ib.Transport == "tcp" && (ib.Runtime == "sing-box" || ib.Runtime == "xray")) ||
			(ib.Protocol == "hysteria2" && ib.Transport == "udp" && (ib.Runtime == "sing-box" || ib.Runtime == "hysteria2"))
		if !supported {
			rejected = append(rejected, ib.Tag)
			continue
		}
		ports[ib.ListenPort] = struct{}{}
		admitted = append(admitted, ib.Tag)
		for _, cl := range ib.Clients {
			if strings.TrimSpace(cl.Email) == "" {
				continue
			}
			counters = append(counters, HistoricalCounter{
				LogicalUser:              cl.Email,
				UpBytes:                  cl.UpBytes,
				DownBytes:                cl.DownBytes,
				AccountingClassification: "historical_non_billable",
			})
		}
	}

	raw, err := json.Marshal(struct {
		Panel    string              `json:"panel"`
		Version  string              `json:"version"`
		Admitted []string            `json:"admitted"`
		Rejected []string            `json:"rejected"`
		Counters []HistoricalCounter `json:"counters"`
	}{
		Panel:    b.SourcePanel,
		Version:  b.SourceVersion,
		Admitted: admitted,
		Rejected: rejected,
		Counters: counters,
	})
	if err != nil {
		return DryRunResult{}, err
	}
	sum := sha256.Sum256(raw)

	return DryRunResult{
		Mode:                     "dry_run",
		JournalDigest:            hex.EncodeToString(sum[:]),
		AdmittedInboundTags:      admitted,
		RejectedInboundTags:      rejected,
		HistoricalCounters:       counters,
		RequiresOperatorApproval: len(rejected) > 0,
	}, nil
}
