package singbox

import (
	"encoding/json"
)

// validateNativeReferences independently checks references that the pinned
// Sing-box syntax checker may accept without resolving. This guards staging
// only: it is not a substitute for locally trusted policy compilation, native
// runtime egress tests, or an independently witnessed applied generation.
func validateNativeReferences(root map[string]json.RawMessage, outbounds []json.RawMessage, route map[string]json.RawMessage) error {
	outboundTags, err := nativeTaggedObjects(outbounds)
	if err != nil {
		return err
	}
	if err := nativeReference(route, "final", outboundTags, true); err != nil {
		return err
	}

	var dns map[string]json.RawMessage
	if raw, present := root["dns"]; present {
		if err := json.Unmarshal(raw, &dns); err != nil || dns == nil {
			return ErrNativeRejected
		}
	}
	var serverTags map[string]bool
	if dns != nil {
		var servers []json.RawMessage
		if err := json.Unmarshal(dns["servers"], &servers); err != nil || len(servers) == 0 {
			return ErrNativeRejected
		}
		serverTags, err = nativeTaggedObjects(servers)
		if err != nil {
			return err
		}
		if err := nativeReference(dns, "final", serverTags, false); err != nil {
			return err
		}
	}
	if err := nativeReference(route, "default_domain_resolver", serverTags, false); err != nil {
		return err
	}
	// The approved compiler emits resolve rules that name a DNS server.
	// Reject unknown server tags without guessing an implicit resolver.
	var rules []map[string]json.RawMessage
	if raw, exists := route["rules"]; exists {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return ErrNativeRejected
		}
		for _, rule := range rules {
			if rule == nil {
				return ErrNativeRejected
			}
			var action string
			if value, exists := rule["action"]; exists {
				if err := json.Unmarshal(value, &action); err != nil {
					return ErrNativeRejected
				}
			}
			if action == "resolve" {
				if err := nativeReference(rule, "server", serverTags, true); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Native tags are explicit, unique and bound to the objects they name.
// No untagged or ambiguous outbound or DNS server can satisfy a reference.
func nativeTaggedObjects(items []json.RawMessage) (map[string]bool, error) {
	tags := make(map[string]bool, len(items))
	for _, item := range items {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(item, &object); err != nil || object == nil {
			return nil, ErrNativeRejected
		}
		var tag string
		if err := json.Unmarshal(object["tag"], &tag); err != nil ||
			tag == "" || tags[tag] {
			return nil, ErrNativeRejected
		}
		tags[tag] = true
	}
	return tags, nil
}

func nativeReference(object map[string]json.RawMessage, key string, tags map[string]bool, required bool) error {
	raw, present := object[key]
	if !present && !required {
		return nil
	}
	var value string
	if !present || json.Unmarshal(raw, &value) != nil || value == "" || !tags[value] {
		return ErrNativeRejected
	}
	return nil
}
