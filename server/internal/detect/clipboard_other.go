//go:build !darwin

package detect

import "detector/internal/config"

// The clipboard detector is macOS only.
func newClipboardDetector(config.ClipboardDetectConfig) Detector { return nil }

// Browser extension scanning is macOS only.
func newExtensionsDetector(config.ExtensionsDetectConfig) Detector { return nil }
