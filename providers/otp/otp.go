package otp

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tedalogger-backend/config"
	"tedalogger-backend/db"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"
)

type OTPProvider interface {
	RequestOTP(user *models.CaptiveUser, cfg *config.Config) error
	ValidateOTP(providedOTP, actualOTP string, otpExpiresAt time.Time) bool
}

type SimpleOTPProvider struct {
	otpLength int
	validity  time.Duration
}

// length = OTP uzunluğu (ör: 6)
// validitySeconds = OTP'nin geçerli olduğu süre (saniye)
func NewSimpleOTPProvider(length int, validitySeconds int) *SimpleOTPProvider {
	return &SimpleOTPProvider{
		otpLength: length,
		validity:  time.Duration(validitySeconds) * time.Second,
	}
}

func (s *SimpleOTPProvider) RequestOTP(user *models.CaptiveUser, cfg *config.Config) error {
	// 1. OTP oluştur
	code := s.generateOTP()
	expiry := time.Now().Add(s.validity)

	// 2. DB'ye yaz
	user.OTPCode = &code
	user.OTPExpiresAt = &expiry
	user.IsOTPVerified = false

	if err := db.DB.Save(&user).Error; err != nil {
		return fmt.Errorf("failed to save OTP to DB: %v", err)
	}

	// 3. SMS gönderecek telefon bilgisi var mı?
	if user.Phone == nil || *user.Phone == "" {
		return fmt.Errorf("user does not have a phone number")
	}
	phone := *user.Phone
	otpText := fmt.Sprintf("OTP Kodunuz: %s", code)

	// 4. SMS API'ye istek
	if err := s.sendOTPViaSMS(
		cfg.PostaGuverciniSMSURL,
		cfg.OTPSendUser,
		cfg.OTPSendPassword,
		phone,
		otpText,
	); err != nil {
		return err
	}

	logger.Logger.Infof("OTP (%s) sent to user ID=%d, phone=%s", code, user.ID, phone)
	return nil
}

func (s *SimpleOTPProvider) ValidateOTP(providedOTP, actualOTP string, otpExpiresAt time.Time) bool {
	// 1. Kod uyuşuyor mu?
	if providedOTP != actualOTP {
		return false
	}
	// 2. Süresi geçmiş mi?
	if time.Now().After(otpExpiresAt) {
		return false
	}
	return true
}

// -------------------------------------------------
// Yardımcı fonksiyonlar
// -------------------------------------------------

// 6 haneli OTP üretir (000000 - 999999 arası)
func (s *SimpleOTPProvider) generateOTP() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

func (s *SimpleOTPProvider) sendOTPViaSMS(
	apiURL, user, password, phoneNumber, otpText string,
) error {
	formData := url.Values{}
	formData.Set("user", user)
	formData.Set("password", password)
	formData.Set("gsm", phoneNumber)
	formData.Set("text", otpText)

	resp, err := http.PostForm(apiURL, formData)
	if err != nil {
		return fmt.Errorf("failed to send SMS request: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read SMS response: %v", err)
	}
	bodyStr := string(bodyBytes)

	// Örnek başarılı cevap: "errno=0&errtext=&message_id=...&charge=-1%"
	if !strings.Contains(bodyStr, "errno=0") {
		return fmt.Errorf("sms service responded with error: %s", bodyStr)
	}

	return nil
}
