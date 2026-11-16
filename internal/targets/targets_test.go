package targets

import (
	"reflect"
	"testing"
)

func TestExpandCIDR(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{"single IPv4", "192.168.1.5", []string{"192.168.1.5"}, false},
		{"single IPv6", "::1", []string{"::1"}, false},
		{
			name: "/30 drops network and broadcast",
			in:   "192.168.1.0/30",
			// /30 has 4 addresses (.0-.3); .0 (network) and .3 (broadcast)
			// are dropped, leaving the two usable host addresses.
			want: []string{"192.168.1.1", "192.168.1.2"},
		},
		{
			name: "/31 (only 2 addresses) is not pruned",
			in:   "192.168.1.0/31",
			want: []string{"192.168.1.0", "192.168.1.1"},
		},
		{"hostname is rejected", "example.com", nil, true},
		{"garbage is rejected", "not-an-ip-or-cidr!!", nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExpandCIDR(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ExpandCIDR(%q) = %v, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExpandCIDR(%q) returned unexpected error: %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ExpandCIDR(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// ExpandHostOrCIDR must behave exactly like ExpandCIDR for real CIDRs/IPs...
func TestExpandHostOrCIDR_AgreesWithExpandCIDR(t *testing.T) {
	for _, in := range []string{"192.168.1.5", "192.168.1.0/30", "192.168.1.0/31"} {
		want, err := ExpandCIDR(in)
		if err != nil {
			t.Fatalf("ExpandCIDR(%q) returned unexpected error: %v", in, err)
		}
		got, err := ExpandHostOrCIDR(in)
		if err != nil {
			t.Fatalf("ExpandHostOrCIDR(%q) returned unexpected error: %v", in, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ExpandHostOrCIDR(%q) = %v, want %v (same as ExpandCIDR)", in, got, want)
		}
	}
}

// ...but, unlike ExpandCIDR, it must accept a bare hostname instead of
// erroring — this is exactly the behavioral difference that kept
// recon.go's expandTarget and dns.go's expandCIDR from being a safe,
// drop-in merge into a single function.
func TestExpandHostOrCIDR_AcceptsHostname(t *testing.T) {
	got, err := ExpandHostOrCIDR("example.com")
	if err != nil {
		t.Fatalf("ExpandHostOrCIDR(\"example.com\") returned unexpected error: %v", err)
	}
	want := []string{"example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExpandHostOrCIDR(\"example.com\") = %v, want %v", got, want)
	}
}
