package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCloudHTTPSyncURL(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		insecure bool
		want     string
	}{
		{
			name:     "host only, secure",
			addr:     "vgpmg.ovp.vn",
			insecure: false,
			want:     "https://vgpmg.ovp.vn/api/sync",
		},
		{
			name:     "host with https scheme, secure",
			addr:     "https://vgpmg.ovp.vn",
			insecure: false,
			want:     "https://vgpmg.ovp.vn/api/sync",
		},
		{
			name:     "host with http scheme, insecure",
			addr:     "http://localhost",
			insecure: true,
			want:     "http://localhost/api/sync",
		},
		{
			name:     "host:port with https scheme",
			addr:     "https://example.com:8443",
			insecure: false,
			want:     "https://example.com:8443/api/sync",
		},
		{
			name:     "host:443 strips port",
			addr:     "example.com:443",
			insecure: false,
			want:     "https://example.com/api/sync",
		},
		{
			name:     "host:80 insecure strips port",
			addr:     "example.com:80",
			insecure: true,
			want:     "http://example.com/api/sync",
		},
		{
			name:     "host:8080 keeps port",
			addr:     "localhost:8080",
			insecure: false,
			want:     "https://localhost:8080/api/sync",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cloudHTTPSyncURL(tt.addr, tt.insecure)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestStripScheme(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{
			name: "https scheme",
			addr: "https://example.com",
			want: "example.com",
		},
		{
			name: "http scheme",
			addr: "http://example.com",
			want: "example.com",
		},
		{
			name: "no scheme",
			addr: "example.com",
			want: "example.com",
		},
		{
			name: "https with port",
			addr: "https://example.com:8443",
			want: "example.com:8443",
		},
		{
			name: "empty string",
			addr: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripScheme(tt.addr)
			assert.Equal(t, tt.want, got)
		})
	}
}
