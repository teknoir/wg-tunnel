package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestCommands(t *testing.T) {
	var out, errb bytes.Buffer
	ctx := context.Background()
	if code := run(ctx, nil, env(nil), &out, &errb); code != 2 || !strings.Contains(errb.String(), "usage") {
		t.Errorf("no args: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := run(ctx, []string{"frobnicate"}, env(nil), &out, &errb); code != 2 || !strings.Contains(errb.String(), "unknown command") {
		t.Errorf("unknown: %d %q", code, errb.String())
	}
	out.Reset()
	if code := run(ctx, []string{"version"}, env(nil), &out, &errb); code != 0 || strings.TrimSpace(out.String()) != "dev" {
		t.Errorf("version: %d %q", code, out.String())
	}
}

func TestInit(t *testing.T) {
	var errb bytes.Buffer
	dir := filepath.Join(t.TempDir(), "wg-agent")
	uid := fmt.Sprint(os.Getuid())
	if code := run(context.Background(), []string{"init", "--dir", dir, "--uid", uid}, env(nil), &bytes.Buffer{}, &errb); code != 0 {
		t.Fatalf("init: %d %q", code, errb.String())
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir: %v %v", fi, err)
	}
	for name, args := range map[string][]string{
		"no flags":     {"init"},
		"no uid":       {"init", "--dir", dir},
		"no dir":       {"init", "--uid", uid},
		"relative dir": {"init", "--dir", "rel", "--uid", uid},
		"extra arg":    {"init", "--dir", dir, "--uid", uid, "x"},
	} {
		errb.Reset()
		if code := run(context.Background(), args, env(nil), &bytes.Buffer{}, &errb); code == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if code := run(context.Background(), []string{"init", "--dir", link, "--uid", uid}, env(nil), &bytes.Buffer{}, &errb); code != 1 {
		t.Errorf("symlink: %d", code)
	}
}

func TestRunRejectsBadConfig(t *testing.T) {
	cases := map[string]map[string]string{
		"empty":     {},
		"no domain": {"DEVICE_ID": "d", "NAMESPACE": "n"},
		"log level": {"DEVICE_ID": "d", "NAMESPACE": "n", "DOMAIN": "x.y", "LOG_LEVEL": "loud"},
	}
	for name, m := range cases {
		var errb bytes.Buffer
		if code := run(context.Background(), []string{"run"}, env(m), &bytes.Buffer{}, &errb); code != 2 {
			t.Errorf("%s: exit %d (%q)", name, code, errb.String())
		}
	}
}
