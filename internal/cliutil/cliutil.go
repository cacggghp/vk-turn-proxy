package cliutil

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

const ContinueExecution = -1

type Builder[T any] func(program string, output io.Writer) (*flag.FlagSet, *T)

type Validator[T any] func(*T) error

func Parse[T any](
	args []string,
	program string,
	stdout io.Writer,
	stderr io.Writer,
	build Builder[T],
	validate Validator[T],
) (T, int) {
	var zero T

	if len(args) == 0 {
		fs, _ := build(program, stdout)
		fs.Usage()
		return zero, 0
	}

	output := stderr
	if hasHelpFlag(args) {
		output = stdout
	}

	fs, opts := build(program, output)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return zero, 0
		}
		return zero, 2
	}

	if validate != nil {
		if err := validate(opts); err != nil {
			Fprintln(stderr, "error:", err)
			fs.Usage()
			return zero, 2
		}
	}

	return *opts, ContinueExecution
}

func Fprintf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func Fprintln(w io.Writer, args ...any) {
	_, _ = fmt.Fprintln(w, args...)
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "-help" || arg == "--help" {
			return true
		}
	}
	return false
}
