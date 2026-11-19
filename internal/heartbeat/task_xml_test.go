package heartbeat

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The template declares encoding="UTF-16", which encoding/xml rejects unless a
// CharsetReader is set. The string is already decoded, so pass it through.
func parseTaskCommand(t *testing.T, doc string) string {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(doc))
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var parsed struct {
		Command string `xml:"Actions>Exec>Command"`
	}
	require.NoError(t, dec.Decode(&parsed), "task XML must be well formed")
	return parsed.Command
}

func TestRenderTaskXML(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"plain path", `C:\Users\dev\AppData\Local\pmg\pmg.exe`},
		{"program files", `C:\Program Files\safedep\pmg\pmg.exe`},
		{"ampersand", `C:\Users\A&B\pmg.exe`},
		{"angle bracket", `C:\Users\a<b\pmg.exe`},
		{"quote", `C:\Users\a"b\pmg.exe`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := renderTaskXML(tt.path, 15, "2026-01-02T03:04:05")
			require.NoError(t, err)

			assert.Equal(t, tt.path, parseTaskCommand(t, out))
			assert.NotContains(t, out, "HighestAvailable")
			assert.Contains(t, out, "PT15M")
			assert.Contains(t, out, "2026-01-02T03:04:05")
			assert.Contains(t, out, "<LogonType>S4U</LogonType>")
		})
	}
}
