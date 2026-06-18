package slice

import (
	"reflect"
	"testing"
)

func TestSelectForRegistration_EmptyRequest(t *testing.T) {
	store := New([]SliceID{{SST: 1, SD: "000001"}, {SST: 2, SD: "000002"}})
	got := store.SelectForRegistration(nil)
	want := []SliceID{{SST: 1, SD: "000001"}, {SST: 2, SD: "000002"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSelectForRegistration_Intersection(t *testing.T) {
	store := New([]SliceID{{SST: 1, SD: "000001"}, {SST: 2, SD: "000002"}})
	got := store.SelectForRegistration([]SliceID{{SST: 1, SD: "000001"}})
	want := []SliceID{{SST: 1, SD: "000001"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSelectForRegistration_NoMatch(t *testing.T) {
	store := New([]SliceID{{SST: 1, SD: "000001"}})
	got := store.SelectForRegistration([]SliceID{{SST: 3, SD: "000003"}})
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestSelectForRegistration_WildcardSD(t *testing.T) {
	store := New([]SliceID{{SST: 1, SD: "000001"}, {SST: 2, SD: "000002"}})
	// SD=="" in requested acts as wildcard: matches any SD for the same SST
	got := store.SelectForRegistration([]SliceID{{SST: 1, SD: ""}})
	want := []SliceID{{SST: 1, SD: "000001"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
