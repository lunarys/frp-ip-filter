package auth

import "testing"

func TestValidateToken(t *testing.T) {
	a := New([]string{"token-a", "token-b"}, nil)

	for _, token := range []string{"token-a", "token-b"} {
		if !a.ValidateToken(token) {
			t.Errorf("expected token %q to be valid", token)
		}
	}
	if a.ValidateToken("nope") {
		t.Error("expected unknown token to be invalid")
	}
	if a.ValidateToken("") {
		t.Error("expected empty token to be invalid")
	}
}

func TestValidateLogin(t *testing.T) {
	a := New(nil, map[string]string{"alice": "hunter2"})

	if !a.ValidateLogin("alice", "hunter2") {
		t.Error("expected alice's login to be valid")
	}
	if a.ValidateLogin("alice", "wrong") {
		t.Error("expected wrong password to be invalid")
	}
	if a.ValidateLogin("carol", "") {
		t.Error("expected unknown user with empty password to be invalid")
	}
}
