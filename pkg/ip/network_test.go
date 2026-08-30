package ip

import "testing"

func TestInNetwork(t *testing.T) {
	inside, err := InNetwork("10.1.2.3", "10.0.0.0/8")
	if err != nil || !inside {
		t.Fatalf("expected inside, err=%v inside=%v", err, inside)
	}
	inside, err = InNetwork("11.0.0.1", "10.0.0.0/8")
	if err != nil || inside {
		t.Fatalf("expected outside, err=%v inside=%v", err, inside)
	}
	inside, err = InNetwork("10.0.0.1", "10.0.0.1")
	if err != nil || !inside {
		t.Fatalf("bare IP equal, err=%v inside=%v", err, inside)
	}
}
