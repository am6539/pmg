//go:build darwin

package ecoscan

import "testing"
import "github.com/stretchr/testify/assert"

func TestParseNetworkMountPointsIdentifiesSMBShare(t *testing.T) {
	output := `/dev/disk1s1 on / (apfs, local, journaled)
//user@server/share on /Volumes/share (smbfs, nodev, nosuid, mounted by user)
/dev/disk2s1 on /Volumes/ExternalSSD (apfs, local, nodev, nosuid, journaled)
`
	result := parseNetworkMountPoints(output)
	assert.True(t, result["/Volumes/share"])
	assert.False(t, result["/Volumes/ExternalSSD"])
	assert.Len(t, result, 1)
}
