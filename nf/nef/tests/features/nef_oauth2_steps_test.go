//go:build functional

package features_test

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cucumber/godog"

	nefcfg "github.com/francurieses/claudia-5gc/nf/nef/internal/config"
	oauth2pkg "github.com/francurieses/claudia-5gc/shared/oauth2"
)

// NEF-002 steps: NEF OAuth2 secret resolution (TS 33.501 §13.4.1) and token verification.

// setEnv sets (or unsets when val is nil) an env var, remembering the original for restoreEnv.
func (c *nefCtx) setEnv(key string, val *string) error {
	if c.envSaved == nil {
		c.envSaved = map[string]*string{}
	}
	if _, ok := c.envSaved[key]; !ok {
		if old, present := os.LookupEnv(key); present {
			c.envSaved[key] = &old
		} else {
			c.envSaved[key] = nil
		}
	}
	if val == nil {
		return os.Unsetenv(key)
	}
	return os.Setenv(key, *val)
}

// restoreEnv restores env vars changed by NEF-002 steps and removes the temp dir.
func (c *nefCtx) restoreEnv() {
	for k, v := range c.envSaved {
		if v == nil {
			_ = os.Unsetenv(k)
		} else {
			_ = os.Setenv(k, *v)
		}
	}
	c.envSaved = nil
	if c.tmpDir != "" {
		_ = os.RemoveAll(c.tmpDir)
		c.tmpDir = ""
	}
}

// startNEFFromConfig runs the real nefcfg.Load against a temp YAML without
// oauth2.secret and rebuilds the NEF with the resolved secret.
func (c *nefCtx) startNEFFromConfig(envSecret *string) error {
	if err := c.setEnv(oauth2pkg.SecretEnv, envSecret); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "nef002-")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	c.tmpDir = dir
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("nf_instance_id: test-nef-001\n"), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := c.setEnv("CONFIG_PATH", &path); err != nil {
		return err
	}
	cfg, err := nefcfg.Load()
	if err != nil {
		return fmt.Errorf("config.Load: %w", err)
	}
	want := oauth2pkg.DefaultDevSecret
	if envSecret != nil {
		want = *envSecret
	}
	if cfg.OAuth2.Secret != want {
		return fmt.Errorf("config.Load resolved secret %q, want %q", cfg.OAuth2.Secret, want)
	}
	if c.nefTS != nil {
		c.nefTS.Close()
	}
	c.nefTS = newNEFWithSecret(c.bsf, c.pcf, cfg.OAuth2.Secret)
	return nil
}

func (c *nefCtx) nefNoSecretEnvUnset() error { return c.startNEFFromConfig(nil) }

func (c *nefCtx) nefNoSecretEnvSet(v string) error { return c.startNEFFromConfig(&v) }

func (c *nefCtx) tokenWithSecret(secret, scope, sub string, ttl time.Duration) error {
	now := time.Now()
	tok, err := oauth2pkg.IssueToken([]byte(secret), &oauth2pkg.Claims{
		Issuer:    "nrf-test",
		Subject:   sub,
		Scope:     scope,
		IssuedAt:  now.Add(-2 * time.Hour).Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	})
	if err != nil {
		return fmt.Errorf("issue token: %w", err)
	}
	c.bearerToken = tok
	return nil
}

func (c *nefCtx) registerOAuth2Steps(sc *godog.ScenarioContext) {
	sc.Step(`^the NEF is configured with no OAuth2 secret and OAUTH2_SECRET is unset$`, c.nefNoSecretEnvUnset)
	sc.Step(`^the NEF is configured with no OAuth2 secret and OAUTH2_SECRET is set to "([^"]*)"$`, c.nefNoSecretEnvSet)
	sc.Step(`^an OAuth2 bearer token signed with the shared/oauth2 DefaultDevSecret with scope "([^"]+)" for scsAsId "([^"]+)"$`,
		func(scope, sub string) error {
			return c.tokenWithSecret(oauth2pkg.DefaultDevSecret, scope, sub, time.Hour)
		})
	sc.Step(`^an OAuth2 bearer token signed with secret "([^"]+)" with scope "([^"]+)" for scsAsId "([^"]+)"$`,
		func(secret, scope, sub string) error { return c.tokenWithSecret(secret, scope, sub, time.Hour) })
	sc.Step(`^an expired OAuth2 bearer token signed with the shared/oauth2 DefaultDevSecret with scope "([^"]+)" for scsAsId "([^"]+)"$`,
		func(scope, sub string) error {
			return c.tokenWithSecret(oauth2pkg.DefaultDevSecret, scope, sub, -time.Hour)
		})
}
