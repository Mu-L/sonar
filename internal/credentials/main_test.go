package credentials

import (
	"os"
	"testing"

	"github.com/raskrebs/sonar/internal/testenv"
)

// Every path sonar resolves from the environment points at a private temp
// directory for the whole of this test binary (step 1A.20).
func TestMain(m *testing.M) { os.Exit(testenv.Run(m)) }
