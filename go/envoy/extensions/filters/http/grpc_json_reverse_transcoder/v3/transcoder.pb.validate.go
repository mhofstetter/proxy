// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/filters/http/grpc_json_reverse_transcoder/v3/transcoder.proto

package grpc_json_reverse_transcoderv3

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on GrpcJsonReverseTranscoder with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *GrpcJsonReverseTranscoder) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on GrpcJsonReverseTranscoder with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// GrpcJsonReverseTranscoderMultiError, or nil if none found.
func (m *GrpcJsonReverseTranscoder) ValidateAll() error {
	return m.validate(true)
}

func (m *GrpcJsonReverseTranscoder) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for DescriptorPath

	// no validation rules for DescriptorBinary

	if wrapper := m.GetMaxRequestBodySize(); wrapper != nil {

		if wrapper.GetValue() <= 0 {
			err := GrpcJsonReverseTranscoderValidationError{
				field:  "MaxRequestBodySize",
				reason: "value must be greater than 0",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	if wrapper := m.GetMaxResponseBodySize(); wrapper != nil {

		if wrapper.GetValue() <= 0 {
			err := GrpcJsonReverseTranscoderValidationError{
				field:  "MaxResponseBodySize",
				reason: "value must be greater than 0",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	// no validation rules for ApiVersionHeader

	if len(errors) > 0 {
		return GrpcJsonReverseTranscoderMultiError(errors)
	}

	return nil
}

// GrpcJsonReverseTranscoderMultiError is an error wrapping multiple validation
// errors returned by GrpcJsonReverseTranscoder.ValidateAll() if the
// designated constraints aren't met.
type GrpcJsonReverseTranscoderMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m GrpcJsonReverseTranscoderMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m GrpcJsonReverseTranscoderMultiError) AllErrors() []error { return m }

// GrpcJsonReverseTranscoderValidationError is the validation error returned by
// GrpcJsonReverseTranscoder.Validate if the designated constraints aren't met.
type GrpcJsonReverseTranscoderValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e GrpcJsonReverseTranscoderValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e GrpcJsonReverseTranscoderValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e GrpcJsonReverseTranscoderValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e GrpcJsonReverseTranscoderValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e GrpcJsonReverseTranscoderValidationError) ErrorName() string {
	return "GrpcJsonReverseTranscoderValidationError"
}

// Error satisfies the builtin error interface
func (e GrpcJsonReverseTranscoderValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sGrpcJsonReverseTranscoder.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = GrpcJsonReverseTranscoderValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = GrpcJsonReverseTranscoderValidationError{}
