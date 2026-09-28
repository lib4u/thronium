package dialer

import (
	"context"
	"github.com/sagernet/sing-box/option"
	"testing"
)

func TestFragmentDefaultDialerRejectsInvalidOptions(t *testing.T) {
	for _, o := range []option.TLSFragmentOptions{
		{Enabled: true, Size: "0", Sleep: "0"}, {Enabled: true, Size: "0-10", Sleep: "0"},
		{Enabled: true, Size: "10-20-30", Sleep: "0"}, {Enabled: true, Size: "65536", Sleep: "0"},
		{Enabled: true, Size: "10", Sleep: "0-1-2"}, {Enabled: true, Size: "10", Sleep: "65536"},
	} {
		if _, err := NewDefault(context.Background(), fragmentDialerOptions(&o, false)); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
}
func TestFragmentDefaultDialerPreservesTFOConflictAndDisabledOptions(t *testing.T) {
	o := option.TLSFragmentOptions{Enabled: true, Size: "10-100", Sleep: "0"}
	d, err := NewDefault(context.Background(), fragmentDialerOptions(&o, false))
	if err != nil || d.dialer4.TLSFragment == nil || d.dialer4.TLSFragment.Size.Max != 100 {
		t.Fatal(d, err)
	}
	if _, err := NewDefault(context.Background(), fragmentDialerOptions(&o, true)); err == nil {
		t.Fatal("TFO conflict accepted")
	}
	o.Enabled = false
	o.Size = "retained disabled text"
	o.Sleep = "retained disabled text"
	d, err = NewDefault(context.Background(), fragmentDialerOptions(&o, true))
	if err != nil || d.dialer4.TLSFragment != nil {
		t.Fatal(d, err)
	}
}

func fragmentDialerOptions(o *option.TLSFragmentOptions, tfo bool) option.DialerOptions {
	var d option.DialerOptions
	d.TLSFragment = o
	d.TCPFastOpen = tfo
	return d
}
