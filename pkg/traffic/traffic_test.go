package traffic

import (
	"testing"
	"time"
)

func TestGetRecentDataLimitsAndCopies(t *testing.T) {
	t.Parallel()
	m := &Manager{data: &TrafficData{Records: []RequestRecord{
		{Timestamp: time.Unix(1, 0), Domain: "one.example"},
		{Timestamp: time.Unix(2, 0), Domain: "two.example"},
		{Timestamp: time.Unix(3, 0), Domain: "three.example"},
	}, DomainStats: map[string]*DomainStats{"one.example": {Domain: "one.example", Requests: 1}}}}

	got := m.GetRecentData(2)
	if len(got.Records) != 2 || got.Records[0].Domain != "two.example" {
		t.Fatalf("unexpected recent records: %#v", got.Records)
	}
	got.Records[0].Domain = "mutated.example"
	got.DomainStats["one.example"].Requests = 99
	if m.data.Records[1].Domain != "two.example" || m.data.DomainStats["one.example"].Requests != 1 {
		t.Fatal("snapshot shares mutable data with manager")
	}
}
