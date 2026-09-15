package main

import "testing"

func TestLoadAuthConfigFromEnv(t *testing.T) {
	t.Setenv("IP_TOKENS", "token-a, token-b")
	t.Setenv("IP_TOKEN_1", "token-c")
	t.Setenv("DYNDNS_LOGINS", "alice:hunter2")
	t.Setenv("DYNDNS_LOGIN_1", "bob:correcthorse")

	cfg, err := loadAuthConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	for _, token := range []string{"token-a", "token-b", "token-c"} {
		if !cfg.validateToken(token) {
			t.Errorf("expected token %q to be valid", token)
		}
	}
	if cfg.validateToken("nope") {
		t.Error("expected unknown token to be invalid")
	}

	if !cfg.validateLogin("alice", "hunter2") {
		t.Error("expected alice's login (comma list) to be valid")
	}
	if !cfg.validateLogin("bob", "correcthorse") {
		t.Error("expected bob's login (indexed var) to be valid")
	}
	if cfg.validateLogin("alice", "wrong") {
		t.Error("expected wrong password to be invalid")
	}
	if cfg.validateLogin("carol", "anything") {
		t.Error("expected unknown user to be invalid")
	}
}

func TestLoadLoginsInvalidEntry(t *testing.T) {
	t.Setenv("DYNDNS_LOGINS", "not-a-valid-pair")

	if _, err := loadAuthConfigFromEnv(); err == nil {
		t.Fatal("expected an error for a login entry missing ':'")
	}
}

func TestIndexedEnvValuesIgnoresUnrelatedVars(t *testing.T) {
	t.Setenv("IP_TOKENS", "should-not-match-indexed")
	t.Setenv("IP_TOKEN_1", "one")
	t.Setenv("IP_TOKEN_2", "two")
	t.Setenv("IP_TOKEN_EXTRA", "should-not-match")

	got := indexedEnvValues("IP_TOKEN_")

	want := map[string]bool{"one": true, "two": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want values matching %v", got, want)
	}
	for _, v := range got {
		if !want[v] {
			t.Errorf("unexpected value %q in %v", v, got)
		}
	}
}
