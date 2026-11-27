// Copyright (c) 2026 AIGuard contributors. Added to the forked package under the same BSD-style license.

package wf

import "golang.org/x/sys/windows"

// BeginTransaction starts an explicit WFP transaction on the session. All
// object changes made before Commit are applied atomically; a crash or Abort
// discards them, so policy switches never leave a half-built rule set.
func (s *Session) BeginTransaction() error {
	return fwpmTransactionBegin0(s.handle, 0)
}

// CommitTransaction commits the transaction started by BeginTransaction.
func (s *Session) CommitTransaction() error {
	return fwpmTransactionCommit0(s.handle)
}

// AbortTransaction discards every change since BeginTransaction.
func (s *Session) AbortTransaction() error {
	return fwpmTransactionAbort0(s.handle)
}

// RulesForProvider lists only the rules in one layer that belong to the given
// provider, so callers never have to parse the (possibly thousands of)
// filters other software installed.
func (s *Session) RulesForProvider(layer LayerID, provider ProviderID) ([]*Rule, error) {
	p := provider
	tmpl := fwpmFilterEnumTemplate0{
		ProviderKey: &p,
		LayerKey:    windows.GUID(layer),
		EnumType:    filterEnumTypeFullyContained,
		ActionMask:  0xFFFFFFFF,
	}
	var enum windows.Handle
	if err := fwpmFilterCreateEnumHandle0(s.handle, &tmpl, &enum); err != nil {
		return nil, err
	}
	defer fwpmFilterDestroyEnumHandle0(s.handle, enum)

	var ret []*Rule
	for {
		rules, err := s.getRulePage(enum)
		if err != nil {
			return nil, err
		}
		if len(rules) == 0 {
			return ret, nil
		}
		ret = append(ret, rules...)
	}
}
