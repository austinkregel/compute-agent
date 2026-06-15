package app

import (
	"reflect"
	"testing"

	"github.com/austinkregel/compute-agent/pkg/config"
)

func TestCombineAllowlist_MergeDefault(t *testing.T) {
	// Empty mode is treated as merge: local floor + CP additions.
	mode, got := combineAllowlist("", []string{"git", "ls"}, []string{"curl"})
	if mode != config.AllowlistModeMerge {
		t.Errorf("mode = %q, want merge", mode)
	}
	want := []string{"git", "ls", "curl"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merge = %v, want %v", got, want)
	}
}

func TestCombineAllowlist_MergeExplicit(t *testing.T) {
	mode, got := combineAllowlist(config.AllowlistModeMerge, []string{"git"}, []string{"curl"})
	if mode != config.AllowlistModeMerge {
		t.Errorf("mode = %q, want merge", mode)
	}
	if !reflect.DeepEqual(got, []string{"git", "curl"}) {
		t.Errorf("merge = %v", got)
	}
}

func TestCombineAllowlist_CPAuthoritative_Replaces(t *testing.T) {
	// cp-authoritative drops the local list entirely — letting the CP tighten an
	// over-permissive local config.
	mode, got := combineAllowlist(config.AllowlistModeCPAuthoritative, []string{"git", "rm -rf /"}, []string{"curl"})
	if mode != config.AllowlistModeCPAuthoritative {
		t.Errorf("mode = %q, want cp-authoritative", mode)
	}
	if !reflect.DeepEqual(got, []string{"curl"}) {
		t.Errorf("cp-authoritative = %v, want [curl] (local dropped)", got)
	}
}

func TestCombineAllowlist_CPAuthoritative_EmptyCPMeansAllowAll(t *testing.T) {
	// An empty CP list under cp-authoritative yields an empty effective list,
	// which the runner treats as allow-all — the operator's choice when they make
	// the CP authoritative and push nothing.
	_, got := combineAllowlist(config.AllowlistModeCPAuthoritative, []string{"git"}, nil)
	if len(got) != 0 {
		t.Errorf("cp-authoritative with empty CP = %v, want empty", got)
	}
}
