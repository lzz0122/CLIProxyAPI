package synthesizer

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestConfigSynthesizerAddsGroups(t *testing.T) {
	synth := NewConfigSynthesizer()
	ctx := &SynthesisContext{
		Config: &config.Config{
			GeminiKey: []config.GeminiKey{
				{APIKey: "gemini-key", Groups: []string{"team-a"}},
			},
			OpenAICompatibility: []config.OpenAICompatibility{
				{
					Name:    "compat",
					BaseURL: "https://example.com",
					Groups:  []string{"provider-group"},
					APIKeyEntries: []config.OpenAICompatibilityAPIKey{
						{APIKey: "entry-key", Groups: []string{"entry-group"}},
					},
				},
			},
		},
		Now:         time.Now(),
		IDGenerator: NewStableIDGenerator(),
	}

	auths, err := synth.Synthesize(ctx)
	if err != nil {
		t.Fatalf("Synthesize() error = %v", err)
	}
	if len(auths) != 2 {
		t.Fatalf("expected 2 auths, got %d", len(auths))
	}
	if got := config.DecodeGroups(auths[0].Attributes["groups"]); len(got) != 1 || got[0] != "team-a" {
		t.Fatalf("gemini groups = %#v", got)
	}
	if got := config.DecodeGroups(auths[1].Attributes["groups"]); len(got) != 1 || got[0] != "entry-group" {
		t.Fatalf("compat groups = %#v", got)
	}
}

func TestFileSynthesizerAddsGroups(t *testing.T) {
	ctx := &SynthesisContext{
		Config: &config.Config{},
		Now:    time.Now(),
	}
	auths := SynthesizeAuthFile(ctx, "/tmp/auth.json", []byte(`{"type":"claude","group":"team-a"}`))
	if len(auths) != 1 {
		t.Fatalf("expected 1 auth, got %d", len(auths))
	}
	if got := config.DecodeGroups(auths[0].Attributes["groups"]); len(got) != 1 || got[0] != "team-a" {
		t.Fatalf("file groups = %#v", got)
	}
}
