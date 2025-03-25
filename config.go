package pcap_parser

import "C"
import (
	"os"
)

type Conf struct {
	IgnoreError bool // Whether to ignore errors (default: true)
	Debug       bool // Debug mode (default: from environment variable DEBUG)
	PrintCJson  bool // Whether to print C JSON (default: false)
}

type Option func(*Conf)

// IgnoreError Whether to ignore the errors
func IgnoreError(ignore bool) Option {
	return func(c *Conf) {
		c.IgnoreError = ignore
	}
}

// PrintCJson controls whether to print the C JSON.
func PrintCJson(print bool) Option {
	return func(c *Conf) {
		c.PrintCJson = print
	}
}

// WithDebug sets the application to debug mode.
func WithDebug(debug bool) Option {
	return func(c *Conf) {
		c.Debug = debug
	}
}

// getDefaultDebug reads the DEBUG environment variable to determine whether debug mode should be enabled.
func getDefaultDebug() bool {
	return os.Getenv("DEBUG") == "true"
}

// NewConfig creates a new Conf instance with the given options, applying defaults where necessary.
func NewConfig(opts ...Option) *Conf {
	conf := &Conf{
		PrintCJson:  false,             // Default: Do not print C JSON
		IgnoreError: true,              // Default: Ignore errors
		Debug:       getDefaultDebug(), // Default: Check DEBUG environment variable for debug mode
	}
	for _, opt := range opts {
		opt(conf)
	}
	return conf
}
