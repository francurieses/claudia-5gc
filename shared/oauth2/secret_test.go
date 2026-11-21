package oauth2

import "testing"

func TestResolveSecret(t *testing.T) {
	tests := []struct {
		name, env, configured, want string
	}{
		{"env wins", "from-env", "from-cfg", "from-env"},
		{"configured", "", "from-cfg", "from-cfg"},
		{"default", "", "", DefaultDevSecret},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(SecretEnv, tc.env)
			if got := ResolveSecret(tc.configured); got != tc.want {
				t.Fatalf("ResolveSecret(%q) = %q, want %q", tc.configured, got, tc.want)
			}
		})
	}
}
