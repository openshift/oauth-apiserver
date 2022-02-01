package internalversion

import (
	"testing"

	"github.com/openshift/oauth-apiserver/pkg/printers"
	userapi "github.com/openshift/oauth-apiserver/pkg/user/apis/user"
)

func TestPrintUserWithDeepCopy(t *testing.T) {
	u := userapi.User{}
	rows, err := printUser(&u, printers.GenerateOptions{})

	if err != nil {
		t.Fatalf("expected no error, but got: %#v", err)
	}
	if len(rows) <= 0 {
		t.Fatalf("expected to have at least one TableRow, but got: %d", len(rows))
	}

	// should not panic
	rows[0].DeepCopy()
}
