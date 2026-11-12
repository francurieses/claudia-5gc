package docker

import "testing"

func TestProjectName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "5gc-rel17"},
		{"   ", "5gc-rel17"},
		{"claudia-5gc", "claudia-5gc"},
		{" custom ", "custom"},
	}
	for _, tc := range tests {
		if got := ProjectName(tc.in); got != tc.want {
			t.Errorf("ProjectName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestClientProjectFilter(t *testing.T) {
	tests := []struct {
		name string
		c    *Client
		want string
	}{
		{"zero value defaults", &Client{}, "com.docker.compose.project=5gc-rel17"},
		{"override", &Client{project: "claudia-5gc"}, "com.docker.compose.project=claudia-5gc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.c.projectFilter().Get("label")
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("label filter = %v, want [%s]", got, tc.want)
			}
		})
	}
}
