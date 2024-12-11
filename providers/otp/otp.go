package otp

import (
	"math/rand"
	"strconv"
	"time"
)

type OTPProvider interface {
	GenerateOTP() string
	ValidateOTP(providedOTP, actualOTP string, otpExpiresAt time.Time) bool
}

// SimpleOTPProvider is a basic implementation of OTPProvider
type SimpleOTPProvider struct {
	otpLength int
	validity  time.Duration
}

// NewSimpleOTPProvider creates a new instance of SimpleOTPProvider
func NewSimpleOTPProvider(length int, validityMinutes int) *SimpleOTPProvider {
	return &SimpleOTPProvider{
		otpLength: length,
		validity:  time.Duration(validityMinutes) * time.Minute,
	}
}

func (s *SimpleOTPProvider) GenerateOTP() string {
	rand.Seed(time.Now().UnixNano())
	min := int64(1)
	max := int64(1)
	for i := 0; i < s.otpLength; i++ {
		min *= 10
		max *= 10
	}
	otp := rand.Int63n(max-min) + min
	return strconv.FormatInt(otp, 10)
}

func (s *SimpleOTPProvider) ValidateOTP(providedOTP, actualOTP string, otpExpiresAt time.Time) bool {
	if providedOTP != actualOTP {
		return false
	}
	if time.Now().After(otpExpiresAt) {
		return false
	}
	return true
}
