package session

import (
	"os"
	"testing"

	"github.com/raskrebs/sonar/internal/testenv"
)

// Every path sonar resolves from the environment points at a private temp
// directory for the whole of this test binary, so nothing here can find the
// developer's own credentials file or config (step 1A.20).
func TestMain(m *testing.M) { os.Exit(testenv.Run(m)) }
