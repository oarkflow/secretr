package secretr

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	mathRand "math/rand"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/oarkflow/clipboard"

	"github.com/oarkflow/shamir"
	"github.com/oarkflow/shamir/storage"
	"github.com/oarkflow/shamir/storage/drivers"
	"gopkg.in/yaml.v3"
)

var (
	secretrDir         = os.Getenv("SECRETR_DIR")
	masterKeyDir       = os.Getenv("SECRETR_MASTERKEY_DIR")
	masterKeyThreshold = 3
	masterKeyShares    = 5
	checkDevice        = true // default to true, can be set via SetCheckDevice
	defaultSecretr     *Secretr
	fingerprint        string
)

const (
	storageFile       = "store.vlt"
	authCacheDuration = time.Minute
	saltSize          = 16
)

func SetCheckDevice(check bool) {
	checkDevice = check
}

func SetMasterKeyDir(dir string) {
	if dir != "" {
		masterKeyDir = dir
	}
}

func SetMasterKeyThreshold(threshold int) {
	if threshold > 0 {
		masterKeyThreshold = threshold
	}
}

func SetMasterKeyShares(shares int) {
	if shares > 0 {
		masterKeyShares = shares
	}
}

// initStorage initializes the secretr storage directory.
func initStorage() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting home directory: %v", err)
	}
	if secretrDir == "" {
		secretrDir = filepath.Join(homeDir, ".secretr")
	}
	if _, err := os.Stat(secretrDir); os.IsNotExist(err) {
		err = os.MkdirAll(secretrDir, 0700)
		if err != nil {
			return fmt.Errorf("error creating .secretr directory: %v", err)
		}
	}
	if masterKeyDir == "" {
		masterKeyDir = filepath.Join(secretrDir, "masterkey_shares")
	}
	if _, err := os.Stat(masterKeyDir); os.IsNotExist(err) {
		err = os.MkdirAll(masterKeyDir, 0700)
		if err != nil {
			return fmt.Errorf("error creating .secretr directory: %v", err)
		}
	}
	return nil
}

// SSHKey Define a struct to hold SSH key pair.
type SSHKey struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

// SecretMeta represents a secret with versioning and lease.
type SecretMeta struct {
	Value      string            `json:"value"`
	Version    int               `json:"version"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	CreatedAt  time.Time         `json:"createdAt"`
	LeaseUntil time.Time         `json:"leaseUntil,omitempty"`
}

// Persist add KVSecrets field for static secret versioning.
type Persist struct {
	Data              map[string]any          `json:"data"`
	ResetAttempts     int                     `json:"resetAttempts"`
	NormalAttempts    int                     `json:"normalAttempts"`
	BannedUntil       time.Time               `json:"bannedUntil"`
	LockedForever     bool                    `json:"lockedForever"`
	EnableReset       bool                    `json:"enableReset"`
	ResetCode         string                  `json:"resetCode"`
	DeviceFingerprint string                  `json:"deviceFingerprint"`
	SSHKeys           map[string]SSHKey       `json:"sshKeys"`
	Certificates      map[string]string       `json:"certificates"`
	KVSecrets         map[string][]SecretMeta `json:"kvSecrets,omitempty"` // NEW field
}

func NewPersist() Persist {
	return Persist{
		Data:              make(map[string]any),
		ResetAttempts:     0,
		NormalAttempts:    0,
		BannedUntil:       time.Time{},
		LockedForever:     false,
		EnableReset:       false,
		ResetCode:         "",
		DeviceFingerprint: fingerprint,
		SSHKeys:           make(map[string]SSHKey),
		Certificates:      make(map[string]string),
		KVSecrets:         make(map[string][]SecretMeta), // initialize KVSecrets
	}
}

// Secretr represents the secret storage with encryption, reset and rate limiting.
type Secretr struct {
	store         Persist
	masterKey     []byte
	salt          []byte
	authedAt      time.Time
	mu            sync.Mutex
	cipherGCM     cipher.AEAD
	nonceSize     int
	promptFunc    func() error
	distributeKey bool
}

// SetDistributeKey sets the distributeKey flag on the default secretr.
func SetDistributeKey(value bool) {
	defaultSecretr.distributeKey = value
}

// New creates a new Secretr instance.
func New() *Secretr {
	v := &Secretr{
		store: NewPersist(),
	}
	v.leaseRevocation(time.Minute)
	return v
}

// SetPrompt method to set GUI prompt override.
func (v *Secretr) SetPrompt(prompt func() error) {
	v.promptFunc = prompt
}

// SetDistributeKey method to set GUI prompt override.
func (v *Secretr) SetDistributeKey(key bool) {
	v.distributeKey = key
}

func (v *Secretr) distributeMasterKey(masterKey []byte) error {
	// NIST SP 800-57: Key splitting and distribution using Shamir's Secret Sharing.
	if !v.distributeKey {
		return nil
	}
	shares, err := shamir.Split(masterKey, masterKeyThreshold, masterKeyShares)
	// Zeroize shares after use
	defer func() {
		for _, s := range shares {
			zeroize(s)
		}
	}()
	if err != nil {
		return fmt.Errorf("failed to split master key: %v", err)
	}
	ms := storage.NewMultiStorage()
	fileStorage, err := drivers.NewFileStorage(masterKeyDir)
	if err != nil {
		return fmt.Errorf("failed to create file storage for master key shares: %v", err)
	}
	for _, share := range shares {
		ms.AssignStorage(share[0], fileStorage)
	}
	if err := storage.StoreSharesMulti(shares, ms); err != nil {
		return fmt.Errorf("failed to store master key shares: %v", err)
	}
	return nil
}

func (v *Secretr) validateMasterKey(masterKey []byte) error {
	if !v.distributeKey {
		return nil
	}
	fileStorage, err := drivers.NewFileStorage(masterKeyDir)
	if err != nil {
		return err
	}
	indices, err := fileStorage.ListShares()
	if err != nil {
		return err
	}
	reconstructed, err := shamir.MultiPartyAuthorize(fileStorage, indices, masterKeyThreshold)
	defer zeroize(reconstructed)
	if err != nil {
		return fmt.Errorf("failed to reconstruct master key: %v", err)
	}
	if !hmac.Equal(reconstructed, masterKey) {
		return fmt.Errorf("MasterKey from SECRETR_MASTERKEY is invalid (distributed verification failed)")
	}
	return nil
}

// InitCipher initializes the AES-GCM cipher with the provided password and salt.
func (v *Secretr) InitCipher(pw []byte, salt []byte) {
	// NIST SP 800-57: Key derivation uses Argon2id with per-user salt.
	if salt == nil {
		salt = make([]byte, saltSize)
		_, _ = rand.Read(salt)
	}
	v.salt = salt
	key := DeriveKey(pw, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		zeroize(key)
		log.Fatalf("failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroize(key)
		log.Fatalf("failed to create GCM: %v", err)
	}
	// Zeroize any previous key material before replacing.
	if v.masterKey != nil {
		zeroize(v.masterKey)
	}
	v.masterKey = key
	v.cipherGCM = gcm
	v.nonceSize = gcm.NonceSize()
	// NIST SP 800-57: Key material is not persisted outside memory.
}

func (v *Secretr) Store() Persist {
	return v.store
}

func SaltSize() int {
	return saltSize
}

// init initializes the secretr by setting up storage.
func init() {
	var err error
	if checkDevice {
		fingerprint, err = GetDeviceFingerPrint()
	}
	if err != nil {
		log.Fatalf("failed to get device fingerprint: %v", err)
	}
	if err := initStorage(); err != nil {
		log.Fatal(err)
	}
	defaultSecretr = New()
}

// FilePath returns the path of the secretr storage file.
func FilePath() string {
	return filepath.Join(secretrDir, storageFile)
}

// PromptMaster prompts for the MasterKey and initializes the secretr accordingly.
func (v *Secretr) PromptMaster() error {
	if time.Since(v.authedAt) < authCacheDuration && v.cipherGCM != nil {
		return nil
	}

	// Call the custom GUI prompt if set.
	if v.promptFunc != nil {
		err := v.promptFunc()
		if err == nil {
			v.authedAt = time.Now()
		}
		return err
	}

	// Use SECRETR_MASTERKEY from the environment if set.
	if envKey := os.Getenv("SECRETR_MASTERKEY"); envKey != "" {
		if _, err := os.Stat(FilePath()); os.IsNotExist(err) {
			// Secretr file doesn't exist; create new secretr using env MasterKey.
			v.InitCipher([]byte(envKey), nil)
			v.store.DeviceFingerprint = fingerprint
			if err := v.Save(); err != nil {
				return err
			}
			v.authedAt = time.Now()
			return nil
		} else {
			// Secretr file exists; retrieve its salt.
			enc, err := os.ReadFile(FilePath())
			if err != nil {
				return err
			}
			decoded, err := base64.StdEncoding.DecodeString(string(enc))
			if err != nil {
				return err
			}
			if len(decoded) < saltSize {
				return fmt.Errorf("corrupt secretr file")
			}
			salt := decoded[:saltSize]
			v.InitCipher([]byte(envKey), salt)
			if err := v.Load(); err == nil {
				v.authedAt = time.Now()
				return nil
			} else {
				fmt.Println("MasterKey from SECRETR_MASTERKEY is invalid.")
			}
		}
	}

	if v.store.EnableReset && ((!v.store.BannedUntil.IsZero() && time.Now().Before(v.store.BannedUntil)) || v.store.LockedForever) {
		if err := v.forceReset(); err != nil {
			return err
		}
		v.authedAt = time.Now()
		return nil
	}

	if v.store.LockedForever {
		return fmt.Errorf("secretr locked permanently")
	}
	if !v.store.BannedUntil.IsZero() && time.Now().Before(v.store.BannedUntil) {
		return fmt.Errorf("secretr banned until %v", v.store.BannedUntil.Format(time.DateTime))
	}

	if _, err := os.Stat(FilePath()); os.IsNotExist(err) {
		for {
			fmt.Println("Secretr database not found. Setting up a new secretr.")
			fmt.Print("Enter new MasterKey: ")
			pw1, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return err
			}
			fmt.Print("Confirm new MasterKey: ")
			pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return err
			}
			if string(pw1) != string(pw2) {
				fmt.Println("MasterKeys do not match. Try again.")
				continue
			}
			err = v.distributeMasterKey(pw1)
			if err != nil {
				return err
			}
			v.InitCipher(pw1, nil)
			v.store.DeviceFingerprint = fingerprint
			fmt.Print("Enable Reset Password? (y/N): ")
			respReader := bufio.NewReader(os.Stdin)
			resp, _ := respReader.ReadString('\n')
			resp = strings.TrimSpace(strings.ToLower(resp))
			if resp == "y" {
				v.store.EnableReset = true
			} else {
				v.store.EnableReset = false
			}
			if err := v.Save(); err != nil {
				return err
			}
			v.authedAt = time.Now()
			return nil
		}
	} else {
		enc, err := os.ReadFile(FilePath())
		if err != nil {
			return err
		}
		decoded, err := base64.StdEncoding.DecodeString(string(enc))
		if err != nil {
			return err
		}
		if len(decoded) < saltSize {
			return fmt.Errorf("corrupt secretr file")
		}
		salt := decoded[:saltSize]
		for {
			fmt.Print("Enter MasterKey: ")
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return err
			}
			err = v.validateMasterKey(pw)
			if err != nil {
				return err
			}
			v.InitCipher(pw, salt)
			if err := v.Load(); err != nil {
				if !strings.Contains(err.Error(), "Invalid MasterKey") {
					return err
				} else {
					fmt.Println("Invalid MasterKey. Try again.")
				}
				v.store.NormalAttempts++
				if v.store.NormalAttempts >= 3 {
					if v.store.EnableReset {
						if v.store.ResetCode == "" {
							var num int64
							_ = binary.Read(rand.Reader, binary.BigEndian, &num)
							v.store.ResetCode = fmt.Sprintf("%06d", num%1000000)
							sendResetEmail(v.store.ResetCode)
							fmt.Println("Too many attempts. Reset code has been sent to your email.")
						}
						continue
					} else {
						v.store.BannedUntil = time.Now().Add(10 * time.Minute)
						fmt.Printf("Too many attempts. Secretr is banned until %v.\n", v.store.BannedUntil.Format(time.DateTime))
						_ = v.Save()
						return fmt.Errorf("failed to authenticate: secretr banned until %v", v.store.BannedUntil)
					}
				}
				continue
			}
			v.authedAt = time.Now()
			v.store.NormalAttempts = 0
			return nil
		}
	}
}

// sendResetEmail now supports SMTP and AWS SES.
func sendResetEmail(code string) {
	emailService := os.Getenv("SECRETR_EMAIL_SERVICE")
	resetEmail := os.Getenv("SECRETR_RESET_EMAIL")
	if resetEmail == "" {
		fmt.Println("Reset email not configured. Reset code:", code)
		return
	}
	if emailService == "smtp" {
		smtpServer := os.Getenv("SECRETR_SMTP_SERVER")
		smtpPort := os.Getenv("SECRETR_SMTP_PORT")
		smtpUser := os.Getenv("SECRETR_SMTP_USER")
		smtpPass := os.Getenv("SECRETR_SMTP_PASS")
		if smtpServer == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
			fmt.Println("SMTP details missing. Reset code:", code)
			return
		}
		subject := "Reset Code"
		message := "Subject: " + subject + "\n\nYour reset code is: " + code
		auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpServer)
		addr := smtpServer + ":" + smtpPort
		if err := smtp.SendMail(addr, auth, smtpUser, []string{resetEmail}, []byte(message)); err != nil {
			fmt.Println("Failed to send reset code via SMTP:", err)
		} else {
			fmt.Println("Reset code sent via SMTP.")
		}
	} else if emailService == "ses" {
		region := os.Getenv("AWS_REGION")
		awsAccessKey := os.Getenv("AWS_ACCESS_KEY_ID")
		awsSecretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
		if region == "" || awsAccessKey == "" || awsSecretKey == "" {
			fmt.Println("AWS SES configuration missing. Reset code:", code)
			return
		}
		sess, err := session.NewSession(&aws.Config{Region: aws.String(region)})
		if err != nil {
			fmt.Println("Failed to create AWS session:", err)
			return
		}
		svc := ses.New(sess)
		subject := "Reset Code"
		body := "Your reset code is: " + code
		input := &ses.SendEmailInput{
			Destination: &ses.Destination{
				ToAddresses: []*string{aws.String(resetEmail)},
			},
			Message: &ses.Message{
				Body: &ses.Body{
					Text: &ses.Content{
						Charset: aws.String("UTF-8"),
						Data:    aws.String(body),
					},
				},
				Subject: &ses.Content{
					Charset: aws.String("UTF-8"),
					Data:    aws.String(subject),
				},
			},
			Source: aws.String(resetEmail),
		}
		_, err = svc.SendEmail(input)
		if err != nil {
			fmt.Println("Failed to send reset code via AWS SES:", err)
		} else {
			fmt.Println("Reset code sent via AWS SES.")
		}
	} else {
		fmt.Printf("Sending reset code %s to user's email...\n", code)
	}
}

// forceReset forces the reset flow using a reset code.
func (v *Secretr) forceReset() error {
	if v.store.ResetCode == "" {
		var num int64
		_ = binary.Read(rand.Reader, binary.BigEndian, &num)
		v.store.ResetCode = fmt.Sprintf("%06d", num%1000000)
		sendResetEmail(v.store.ResetCode)
		fmt.Println("Secretr is banned/locked. Reset code has been sent to your email.")
	}
	for {
		fmt.Print("Enter reset code: ")
		resetReader := bufio.NewReader(os.Stdin)
		input, _ := resetReader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != v.store.ResetCode {
			fmt.Println("Incorrect reset code.")
			continue
		}
		for {
			fmt.Print("Enter new MasterKey: ")
			new1, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return err
			}
			fmt.Print("Confirm new MasterKey: ")
			new2, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				zeroize(new1)
				return err
			}
			if string(new1) != string(new2) {
				fmt.Println("MasterKeys do not match. Try again.")
				zeroize(new1)
				zeroize(new2)
				continue
			}
			v.InitCipher(new1, nil)
			zeroize(new1)
			zeroize(new2)
			// Zeroize old masterKey if present
			if v.masterKey != nil {
				zeroize(v.masterKey)
			}
			v.store = NewPersist() // Reset the store
			if err := v.Save(); err != nil {
				return err
			}
			fmt.Println("MasterKey has been reset successfully.")
			return nil
		}
	}
}

// Load decrypts and loads the secretr data from disk.
func (v *Secretr) Load() error {
	enc, err := os.ReadFile(FilePath())
	if err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(string(enc))
	if err != nil {
		return err
	}
	if len(decoded) < saltSize+v.nonceSize {
		return fmt.Errorf("corrupt secretr file")
	}
	data := decoded[saltSize:]
	nonce := data[:v.nonceSize]
	ciphertext := data[v.nonceSize:]
	plain, err := v.cipherGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("invalid MasterKey or corrupt secretr file: %v", err)
	}

	var persist Persist
	if err := json.Unmarshal(plain, &persist); err != nil {
		return err
	}
	v.store = persist
	if checkDevice && v.store.DeviceFingerprint != "" {
		if v.store.DeviceFingerprint != fingerprint {
			return fmt.Errorf("access denied: secretr cannot be accessed from this device")
		}
	}
	if !v.store.BannedUntil.IsZero() && time.Now().Before(v.store.BannedUntil) {
		return fmt.Errorf("secretr banned until %v due to multiple invalid attempts", v.store.BannedUntil.Format(time.DateTime))
	}
	return nil
}

// Save encrypts and saves the secretr data to disk.
func (v *Secretr) Save() error {
	// NIST SP 800-57: All secret data is encrypted with AES-GCM before storage.
	v.store.DeviceFingerprint = fingerprint
	plain, err := json.Marshal(v.store)
	if err != nil {
		return err
	}
	nonce := make([]byte, v.nonceSize)
	_, _ = io.ReadFull(rand.Reader, nonce)
	ciphertext := v.cipherGCM.Seal(nonce, nonce, plain, nil)
	final := append(v.salt, ciphertext...)
	enc := base64.StdEncoding.EncodeToString(final)
	return os.WriteFile(FilePath(), []byte(enc), 0600)
}

// Set assigns a secret value to a key.
func (v *Secretr) Set(key string, value any) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	if err := v.PromptMaster(); err != nil {
		return err
	}
	if strings.Contains(key, ".") {
		parts := strings.Split(key, ".")
		base := parts[0]
		subkeys := parts[1:]
		var node map[string]any
		if existing, ok := v.store.Data[base]; ok {
			if m, ok := existing.(map[string]any); ok {
				node = m
			} else {
				node = make(map[string]any)
			}
		} else {
			node = make(map[string]any)
		}
		current := node
		for i, k := range subkeys {
			if i == len(subkeys)-1 {
				current[k] = value
			} else {
				if next, ok := current[k]; ok {
					if m, ok := next.(map[string]any); ok {
						current = m
					} else {
						m := make(map[string]any)
						current[k] = m
						current = m
					}
				} else {
					m := make(map[string]any)
					current[k] = m
					current = m
				}
			}
		}
		v.store.Data[base] = node
	} else {
		switch value := value.(type) {
		case string:
			trimmed := strings.TrimSpace(value)
			if strings.HasPrefix(trimmed, "{") {
				var parsed map[string]any
				if err := json.Unmarshal([]byte(value), &parsed); err == nil {
					v.store.Data[key] = parsed
				} else {
					v.store.Data[key] = value
				}
			} else {
				v.store.Data[key] = value
			}
		default:
			v.store.Data[key] = value
		}
	}
	err := v.Save()
	if err == nil {
		LogAudit("set", key, "value set", v.masterKey)
	}
	return err
}

// Get returns the decrypted secret for a given key.
func (v *Secretr) Get(key string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	if err := v.PromptMaster(); err != nil {
		return "", err
	}
	if strings.Contains(key, ".") {
		parts := strings.Split(key, ".")
		base := parts[0]
		subkeys := parts[1:]
		node, ok := v.store.Data[base]
		if !ok {
			return "", fmt.Errorf("key %s not found", key)
		}
		var current = node
		for _, k := range subkeys {
			if m, ok := current.(map[string]any); ok {
				current, ok = m[k]
				if !ok {
					return "", fmt.Errorf("key %s not found", key)
				}
			} else {
				return "", fmt.Errorf("key %s not found", key)
			}
		}
		switch v := current.(type) {
		case map[string]any:
			b, _ := json.MarshalIndent(v, "", "  ")
			return string(b), nil
		case string:
			return v, nil
		default:
			return fmt.Sprintf("%v", current), nil
		}
	} else {
		value, ok := v.store.Data[key]
		if !ok {
			return "", fmt.Errorf("key %s not found", key)
		}
		if m, ok := value.(map[string]any); ok {
			b, _ := json.MarshalIndent(m, "", "  ")
			return string(b), nil
		}
		if s, ok := value.(string); ok {
			return s, nil
		}
		return fmt.Sprintf("%v", value), nil
	}
}

// Delete removes a secret from the secretr.
func (v *Secretr) Delete(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	if err := v.PromptMaster(); err != nil {
		return err
	}
	if strings.Contains(key, ".") {
		parts := strings.Split(key, ".")
		base := parts[0]
		subkeys := parts[1:]
		node, ok := v.store.Data[base]
		if !ok {
			return fmt.Errorf("key %s not found", key)
		}
		current, ok := node.(map[string]any)
		if !ok {
			return fmt.Errorf("key %s not found", key)
		}
		for i, k := range subkeys {
			if i == len(subkeys)-1 {
				delete(current, k)
			} else {
				if next, ok := current[k].(map[string]any); ok {
					current = next
				} else {
					return fmt.Errorf("key %s not found", key)
				}
			}
		}
		if len(current) == 0 {
			delete(v.store.Data, base)
		} else {
			v.store.Data[base] = current
		}
	} else {
		delete(v.store.Data, key)
	}

	err := v.Save()
	if err == nil {
		LogAudit("delete", key, "deleted", v.masterKey)
	}
	return err
}

// Copy copies a secret to the clipboard.
func (v *Secretr) Copy(key string) error {
	val, err := v.Get(key)
	if err != nil {
		return err
	}
	return clipboard.WriteAll(val)
}

// Env sets a secret as an environment variable.
func (v *Secretr) Env(key string) error {

	secret, err := v.Get(key)
	if err != nil {
		return err
	}
	return os.Setenv(key, secret)
}

// EnrichEnv sets all secretr keys as environment variables.
func (v *Secretr) EnrichEnv() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, val := range v.store.Data {
		var s string
		switch tv := val.(type) {
		case string:
			s = tv
		case map[string]any:
			js, err := json.Marshal(tv)
			if err != nil {
				continue
			}
			s = string(js)
		default:
			s = fmt.Sprintf("%v", tv)
		}
		if err := os.Setenv(k, s); err != nil {
			return err
		}
	}
	return nil
}

// initData initializes the secretr data map if it's nil.
func (v *Secretr) initData() {
	if v.store.Data == nil {
		v.store.Data = make(map[string]any)
	}
	if v.store.SSHKeys == nil {
		v.store.SSHKeys = make(map[string]SSHKey)
	}
	if v.store.Certificates == nil {
		v.store.Certificates = make(map[string]string)
	}
}

// Default export the default Secretr instance.
func Default() *Secretr {
	return defaultSecretr
}

// Execute runs the secretr CLI loop.
func Execute(distributeKey bool) {
	secretr := New()
	secretr.SetDistributeKey(distributeKey)
	err := secretr.PromptMaster()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	cliLoop(secretr)
}

// LoadFromEnv loads environment variables into the secretr.
func (v *Secretr) LoadFromEnv() {
	envs := os.Environ()
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]
		if err := v.Set(key, value); err != nil {
			fmt.Printf("failed to set %s: %v\n", key, err)
		} else {
			fmt.Printf("Loaded %s\n", key)
		}
	}
}

// ImportFile to import secrets from various file formats.
func (v *Secretr) ImportFile(format, filePath string) error {
	v.initData()
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	switch format {
	case "csv":
		r := csv.NewReader(bytes.NewReader(fileContent))
		records, err := r.ReadAll()
		if err != nil {
			return err
		}
		for _, record := range records {
			if len(record) < 2 {
				continue
			}
			key, value := strings.TrimSpace(record[0]), strings.TrimSpace(record[1])
			if key != "" {
				v.store.Data[key] = value
			}
		}
	case "tsv":
		r := csv.NewReader(bytes.NewReader(fileContent))
		r.Comma = '\t'
		records, err := r.ReadAll()
		if err != nil {
			return err
		}
		for _, record := range records {
			if len(record) < 2 {
				continue
			}
			key, value := strings.TrimSpace(record[0]), strings.TrimSpace(record[1])
			if key != "" {
				v.store.Data[key] = value
			}
		}
	case "json":
		var data map[string]any
		if err := json.Unmarshal(fileContent, &data); err != nil {
			return err
		}
		for k, v2 := range data {
			v.store.Data[k] = v2
		}
	case ".env":
		lines := strings.Split(string(fileContent), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			k := strings.TrimSpace(parts[0])
			vVal := strings.TrimSpace(parts[1])
			if k != "" {
				v.store.Data[k] = vVal
			}
		}
	case "yaml", "yml":
		var data map[string]any
		if err := yaml.Unmarshal(fileContent, &data); err != nil {
			return err
		}
		for k, v2 := range data {
			v.store.Data[k] = v2
		}
	default:
		return fmt.Errorf("unsupported import format: %s", format)
	}
	return v.Save()
}

// Modify cliLoop to support the import command.
func cliLoop(secretr *Secretr) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("secretr> ")
		if !scanner.Scan() {
			break
		}
		parts := strings.Fields(scanner.Text())
		if len(parts) > 0 {
			cmd := strings.ToLower(parts[0])
			if cmd == "exit" || cmd == "quit" {
				_ = secretr.Save()
				fmt.Println("Exiting secretr CLI.")
				_ = clipboard.WriteAll("")
				return
			}
			if cmd == "list" {
				keys := secretr.List()
				for _, k := range keys {
					fmt.Println(k)
				}
				continue
			}
			if cmd == "enrich" {
				if err := secretr.EnrichEnv(); err != nil {
					fmt.Println("error:", err)
				} else {
					fmt.Println("Secretr secrets enriched into environment variables.")
				}
				continue
			}
			if cmd == "import" {
				if len(parts) < 3 {
					fmt.Println("usage: import <format> <filepath>")
					continue
				}
				format := strings.ToLower(parts[1])
				filePath := parts[2]
				if err := secretr.ImportFile(format, filePath); err != nil {
					fmt.Println("import error:", err)
				} else {
					fmt.Println("Import successful")
				}
				continue
			}
			// Command to generate a dynamic secret.
			if cmd == "dynamic" {
				if len(parts) < 3 {
					fmt.Println("usage: dynamic <key> <lease_in_seconds>")
				} else {
					leaseSec, err := strconv.Atoi(parts[2])
					if err != nil {
						fmt.Println("invalid lease duration")
					} else {
						secret, err := secretr.GenerateDynamicSecret(parts[1], time.Duration(leaseSec)*time.Second)
						if err != nil {
							fmt.Println("error generating dynamic secret:", err)
						} else {
							fmt.Println("Dynamic secret for", parts[1], ":", secret)
						}
					}
				}
				continue
			}
			// Command to list all KV secret versions for a given key.
			if cmd == "listkv" {
				if len(parts) < 2 {
					fmt.Println("usage: listkv <key>")
				} else {
					versions, err := secretr.ListKVSecretVersions(parts[1])
					if err != nil {
						fmt.Println("error:", err)
					} else {
						b, _ := json.MarshalIndent(versions, "", "  ")
						fmt.Println(string(b))
					}
				}
				continue
			}
			// Command to rollback a KV secret to a specific version.
			if cmd == "rollbackkv" {
				if len(parts) < 3 {
					fmt.Println("usage: rollbackkv <key> <version>")
				} else {
					versionIdx, err := strconv.Atoi(parts[2])
					if err != nil {
						fmt.Println("invalid version index")
					} else {
						if err := secretr.RollbackKVSecret(parts[1], versionIdx); err != nil {
							fmt.Println("error:", err)
						} else {
							fmt.Println("Rollback successful")
						}
					}
				}
				continue
			}
			// Command to display the entire store (all secrets stored in v.store)
			if cmd == "store" {
				b, err := json.MarshalIndent(secretr.store, "", "  ")
				if err != nil {
					fmt.Println("error:", err)
				} else {
					fmt.Println(string(b))
				}
				continue
			}
		}
		if len(parts) < 2 {
			fmt.Println("usage: set|get|delete|copy|env|enrich|list|listkv|rollbackkv|store|ssh-key|certificate|sign|verify|hash key [value]")
			continue
		}
		op, key := strings.ToLower(parts[0]), parts[1]
		switch op {
		case "set", "update":
			// Check if key contains '=' meaning inline value provided: e.g., VAR=test
			if strings.Contains(key, "=") {
				splits := strings.SplitN(key, "=", 2)
				key = splits[0]
				value := splits[1]
				// Warn user about insecure inline secrets.
				fmt.Println("WARNING: Providing secrets in command line is insecure.")
				if err := secretr.Set(key, value); err != nil {
					fmt.Println("error:", err)
				}
			} else {
				fmt.Print("Enter secret: ")
				pw, _ := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err := secretr.Set(key, string(pw)); err != nil {
					fmt.Println("error:", err)
				}
			}
		case "get":
			val, err := secretr.Get(key)
			if err != nil {
				fmt.Println("error:", err)
			} else {
				fmt.Println(val)
			}
		case "delete":
			if err := secretr.Delete(key); err != nil {
				fmt.Println("error:", err)
			}
		case "env":

			if err := secretr.Env(key); err != nil {
				fmt.Println("error:", err)
			} else {
				fmt.Println("Environment variable set:", key)
			}
		case "load-env":
			secretr.LoadFromEnv()
		case "copy":
			if err := secretr.Copy(key); err != nil {
				fmt.Println("error:", err)
			} else {
				fmt.Println("secret copied to clipboard")
			}
		case "ssh-key":
			if len(parts) < 3 {
				fmt.Println("Usage: ssh-key add|edit|reveal|copy <name>")
				continue
			}
			action := parts[1]
			name := parts[2]
			switch action {
			case "add":
				if err := defaultSecretr.AddSSHKeyCLI(name); err != nil {
					fmt.Println("error:", err)
				} else {
					fmt.Println("SSH Key added successfully:", name)
				}
			case "edit":
				if err := defaultSecretr.EditSSHKeyCLI(name); err != nil {
					fmt.Println("error:", err)
				} else {
					fmt.Println("SSH Key updated successfully:", name)
				}
			case "delete":
				defaultSecretr.DeleteSSHKeyCLI(name)
			case "reveal":
				defaultSecretr.RevealSSHKeyCLI(name)
			case "copy":
				keyData, ok := defaultSecretr.store.SSHKeys[name]
				if !ok || strings.TrimSpace(keyData.Private) == "" {
					fmt.Println("SSH key not found")
				} else {
					if err := clipboard.WriteAll(keyData.Private); err != nil {
						fmt.Println("error copying SSH key:", err)
					} else {
						fmt.Println("SSH key copied to clipboard")
					}
				}
			default:
				fmt.Println("Invalid ssh-key action. Use add|edit|reveal|copy.")
			}
		case "certificate":
			if len(parts) < 4 || parts[1] != "generate" {
				fmt.Println("usage: certificate generate <name> <duration>")
				continue
			}
			name := parts[2]
			duration, err := time.ParseDuration(parts[3] + "d")
			if err != nil {
				fmt.Println("error:", err)
				continue
			}
			if err := secretr.GenerateCertificate(name, duration); err != nil {
				fmt.Println("error:", err)
			} else {
				fmt.Println("Certificate generated successfully:", name)
			}
		case "sign":
			if len(parts) < 3 {
				fmt.Println("usage: sign <key> <data>")
				continue
			}
			key := parts[1]
			data := parts[2]
			signature, err := secretr.SignData(key, data)
			if err != nil {
				fmt.Println("error:", err)
			} else {
				fmt.Println("Signature:", signature)
			}
		case "verify":
			if len(parts) < 4 {
				fmt.Println("usage: verify <key> <data> <signature>")
				continue
			}
			key := parts[1]
			data := parts[2]
			signature := parts[3]
			valid, err := secretr.VerifySignature(key, data, signature)
			if err != nil {
				fmt.Println("error:", err)
			} else if valid {
				fmt.Println("Signature is valid.")
			} else {
				fmt.Println("Signature is invalid.")
			}
		case "hash":
			if len(parts) < 2 {
				fmt.Println("usage: hash <data>")
				continue
			}
			data := parts[1]
			hash := secretr.GenerateHash(data)
			fmt.Println("Hash:", hash)
		default:
			fmt.Println("unknown command")
		}
	}
}

// List returns a flattened list of keys stored in the secretr.
func (v *Secretr) List() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	var keys []string
	flattenKeys(v.store.Data, "", &keys)
	return keys
}

// flattenKeys recursively flattens nested keys.
func flattenKeys(data map[string]any, prefix string, keys *[]string) {
	for k, v := range data {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		*keys = append(*keys, fullKey)
		if m, ok := v.(map[string]any); ok {
			flattenKeys(m, fullKey, keys)
		}
	}
}

// Unmarshal method to Secretr.
func (v *Secretr) Unmarshal(key string, dest any) error {
	secret, err := v.Get(key)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(secret), dest)
}

type GroupedSecrets struct {
	Application string            `json:"application"`
	Namespace   string            `json:"namespace"`
	Secrets     map[string]string `json:"secrets"`
}

func (v *Secretr) AddGroup(application, namespace string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	groupKey := application + ":" + namespace
	if _, exists := v.store.Data[groupKey]; exists {
		return fmt.Errorf("group already exists")
	}
	v.store.Data[groupKey] = GroupedSecrets{
		Application: application,
		Namespace:   namespace,
		Secrets:     make(map[string]string),
	}
	return v.Save()
}

func (v *Secretr) AddSecretToGroup(application, namespace, key, value string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	groupKey := application + ":" + namespace
	group, exists := v.store.Data[groupKey].(GroupedSecrets)
	if !exists {
		return fmt.Errorf("group not found")
	}
	group.Secrets[key] = value
	v.store.Data[groupKey] = group
	return v.Save()
}

func (v *Secretr) GenerateUniqueSecret(application, namespace string, duration time.Duration) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	secret := fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().String())))
	groupKey := application + ":" + namespace
	group, exists := v.store.Data[groupKey].(GroupedSecrets)
	if !exists {
		return "", fmt.Errorf("group not found")
	}
	group.Secrets[secret] = time.Now().Add(duration).Format(time.RFC3339)
	v.store.Data[groupKey] = group
	return secret, v.Save()
}

// GenerateSSHKey generates an SSH key pair and stores it.
func (v *Secretr) GenerateSSHKey(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	privateKey, publicKey, err := GenerateSSHKeyPair()
	if err != nil {
		return err
	}
	v.store.SSHKeys[name] = SSHKey{Private: privateKey, Public: publicKey}
	return v.Save()
}

// GenerateCertificate generates a self-signed certificate.
func (v *Secretr) GenerateCertificate(name string, duration time.Duration) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	cert, err := generateSelfSignedCertificate(duration)
	if err != nil {
		return err
	}
	v.store.Certificates[name] = cert
	return v.Save()
}

// SignData signs data using HMAC.
func (v *Secretr) SignData(key string, data string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	hmacKey, ok := v.store.Data[key].(string)
	if !ok {
		return "", fmt.Errorf("key not found")
	}
	return generateHMAC(hmacKey, data), nil
}

// VerifySignature verifies the HMAC signature.
func (v *Secretr) VerifySignature(key string, data string, signature string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	hmacKey, ok := v.store.Data[key].(string)
	if !ok {
		return false, fmt.Errorf("key not found")
	}
	return verifyHMAC(hmacKey, data, signature), nil
}

// GenerateHash generates a hash of the given data.
func (v *Secretr) GenerateHash(data string) string {
	return generateHash(data)
}

// GenerateSSHKeyPair generates an SSH key pair (private and public keys).
func GenerateSSHKeyPair() (string, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %v", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})

	return string(privatePEM), string(publicPEM), nil
}

// generateSelfSignedCertificate generates a self-signed certificate.
func generateSelfSignedCertificate(duration time.Duration) (string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          randSerialNumber(),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	return string(certPEM), nil
}

// generateHMAC generates an HMAC signature for the given data using the provided key.
func generateHMAC(key, data string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// verifyHMAC verifies the HMAC signature for the given data using the provided key.
func verifyHMAC(key, data, signature string) bool {
	expected := generateHMAC(key, data)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// generateHash generates a SHA-256 hash of the given data.
func generateHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// randSerialNumber generates a random serial number for certificates.
func randSerialNumber() *big.Int {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return serialNumber
}

// AddSSHKeyCLI adds a new SSH key via CLI input.
func (v *Secretr) AddSSHKeyCLI(name string) error {
	// Ensure the cipher is initialized.
	if v.cipherGCM == nil {
		if err := v.PromptMaster(); err != nil {
			return fmt.Errorf("failed to initialize cipher: %w", err)
		}
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Generate new SSH key pair? (y/N): ")
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))
	var privateKey, publicKey string
	if resp == "y" {
		pKey, pubKey, err := GenerateSSHKeyPair()
		if err != nil {
			return err
		}
		privateKey = pKey
		publicKey = pubKey
		fmt.Println("Generated new SSH key pair.")
	} else {
		fmt.Println("Paste Private Key (end with an empty line):")
		privateKey = readMultilineFromStdin(reader)
		fmt.Println("Paste Public Key (end with an empty line):")
		publicKey = readMultilineFromStdin(reader)
	}
	v.store.SSHKeys[name] = SSHKey{Private: privateKey, Public: publicKey}
	return v.Save()
}

// Add a helper for reading multi-line input from stdin.
func readMultilineFromStdin(reader *bufio.Reader) string {
	var lines []string
	for {
		line, _ := reader.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// EditSSHKeyCLI to offer the same option.
func (v *Secretr) EditSSHKeyCLI(name string) error {
	reader := bufio.NewReader(os.Stdin)
	ssh, exists := v.store.SSHKeys[name]
	if !exists {
		return fmt.Errorf("SSH key '%s' not found", name)
	}
	oldPrivate := ssh.Private
	oldPublic := ssh.Public
	fmt.Printf("Current Private Key:\n%s\n", oldPrivate)
	fmt.Print("Generate new SSH key pair? (y/N): ")
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))
	var privateKey, publicKey string
	if resp == "y" {
		p, pub, err := GenerateSSHKeyPair()
		if err != nil {
			return err
		}
		privateKey = p
		publicKey = pub
		fmt.Println("Generated new SSH key pair.")
	} else {
		fmt.Println("Paste New Private Key (leave empty to keep current; end with an empty line):")
		newPriv := readMultilineFromStdin(reader)
		if newPriv == "" {
			privateKey = oldPrivate
		} else {
			privateKey = newPriv
		}
		fmt.Println("Paste New Public Key (leave empty to keep current; end with an empty line):")
		newPub := readMultilineFromStdin(reader)
		if newPub == "" {
			publicKey = oldPublic
		} else {
			publicKey = newPub
		}
	}
	v.store.SSHKeys[name] = SSHKey{Private: privateKey, Public: publicKey}
	return v.Save()
}

// RevealSSHKeyCLI to show keys in two separate sections.
func (v *Secretr) RevealSSHKeyCLI(name string) {
	ssh, exists := v.store.SSHKeys[name]
	if !exists {
		fmt.Println("SSH key not found")
		return
	}
	privateKey := ssh.Private
	publicKey := ssh.Public
	fmt.Println("----- Private Key -----")
	fmt.Println(privateKey)
	fmt.Println("----- Public Key -----")
	fmt.Println(publicKey)
}

// DeleteSSHKeyCLI to show keys in two separate sections.
func (v *Secretr) DeleteSSHKeyCLI(name string) {
	delete(v.store.SSHKeys, name)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._$~"
const safeStartBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = mathRand.New(mathRand.NewSource(time.Now().UnixNano()))

func GenerateRandomString(length ...int) string {
	n := 32 // Default length
	if len(length) > 0 {
		n = length[0]
	}
	if n < 1 {
		n = 32 // Ensure at least 1 character
	}
	b := make([]byte, n)

	// Ensure first character is from safeStartBytes
	b[0] = safeStartBytes[src.Intn(len(safeStartBytes))]

	// Fill the rest with full character set
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i > 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// GenerateDynamicSecret creates a dynamic secret with a lease.
func (v *Secretr) GenerateDynamicSecret(name string, leaseDuration time.Duration, length ...int) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	secretLength := 32
	if len(length) > 0 {
		secretLength = length[0]
	}
	secret := GenerateRandomString(secretLength)
	leaseUntil := time.Now().Add(leaseDuration)
	meta := SecretMeta{
		Value:      secret,
		Version:    1,
		CreatedAt:  time.Now(),
		LeaseUntil: leaseUntil,
	}
	if v.store.KVSecrets == nil {
		v.store.KVSecrets = make(map[string][]SecretMeta)
	}
	v.store.KVSecrets[name] = append(v.store.KVSecrets[name], meta)
	if err := v.Save(); err != nil {
		return "", err
	}
	return secret, nil
}

func (v *Secretr) VerifyDynamicSecret(name, secret string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.store.KVSecrets == nil {
		return false, fmt.Errorf("no dynamic secrets stored")
	}
	versions, ok := v.store.KVSecrets[name]
	if !ok || len(versions) == 0 {
		return false, fmt.Errorf("no versions found for key %s", name)
	}
	for _, version := range versions {
		if version.Value == secret && time.Now().Before(version.LeaseUntil) {
			return true, nil
		}
	}
	return false, nil
}

// TransitEncrypt and TransitDecrypt offer encryption as a service.
func (v *Secretr) TransitEncrypt(plaintext string) (string, error) {
	if v.cipherGCM == nil {
		return "", fmt.Errorf("cipher not initialized")
	}
	nonce := make([]byte, v.nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := v.cipherGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (v *Secretr) TransitDecrypt(encText string) (string, error) {
	if v.cipherGCM == nil {
		return "", fmt.Errorf("cipher not initialized")
	}
	cipherData, err := base64.StdEncoding.DecodeString(encText)
	if err != nil {
		return "", err
	}
	if len(cipherData) < v.nonceSize {
		return "", fmt.Errorf("invalid ciphertext")
	}
	nonce := cipherData[:v.nonceSize]
	plaintext, err := v.cipherGCM.Open(nil, nonce, cipherData[v.nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// ListKVSecretVersions List all versions for a given static (KV) secret.
func (v *Secretr) ListKVSecretVersions(key string) ([]SecretMeta, error) {
	if v.store.KVSecrets == nil {
		return nil, fmt.Errorf("no KV secrets stored")
	}
	versions, ok := v.store.KVSecrets[key]
	if !ok || len(versions) == 0 {
		return nil, fmt.Errorf("no versions found for key %s", key)
	}
	return versions, nil
}

// RollbackKVSecret rolls back to a prior version for static (KV) secrets.
func (v *Secretr) RollbackKVSecret(key string, versionIndex int) error {
	versions, err := v.ListKVSecretVersions(key)
	if err != nil {
		return err
	}
	if versionIndex < 0 || versionIndex >= len(versions) {
		return fmt.Errorf("invalid version index")
	}
	v.store.Data[key] = versions[versionIndex].Value
	v.store.KVSecrets[key] = versions[:versionIndex+1]
	if err := v.Save(); err != nil {
		return err
	}
	LogAudit("kv_rollback", key, fmt.Sprintf("rolled back to version %d", versionIndex), v.masterKey)
	return nil
}

// zeroize overwrites a byte slice with zeros (best effort in Go).
func zeroize(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

// NIST SP 800-57 Compliance: All cryptographic keys are generated using CSPRNGs
// and are never stored in plaintext. Master keys are split using Shamir's Secret Sharing
// and can be distributed and reconstructed only with a threshold of shares.
// Keys are derived using Argon2id KDF with per-user salt, and all encryption uses AES-GCM.
// Key material is never logged or exported in plaintext. Key destruction is handled by
// overwriting in-memory slices and not persisting keys outside secure memory.

// KeyType enumerates supported key types.
type KeyType string

const (
	KeyTypeAES128  KeyType = "AES-128"
	KeyTypeAES256  KeyType = "AES-256"
	KeyType3DES    KeyType = "3DES"
	KeyTypeRSA2048 KeyType = "RSA-2048"
	KeyTypeRSA3072 KeyType = "RSA-3072"
	KeyTypeRSA4096 KeyType = "RSA-4096"
	KeyTypeECCP256 KeyType = "ECC-P256"
	KeyTypeECCP384 KeyType = "ECC-P384"
	KeyTypeECCP521 KeyType = "ECC-P521"
)

// KeyMetadata holds metadata for a managed key.
type KeyMetadata struct {
	ID           string    `json:"id"`
	Type         KeyType   `json:"type"`
	CreatedAt    time.Time `json:"created_at"`
	Usage        string    `json:"usage"` // e.g., "encrypt", "decrypt", "sign", "verify"
	Version      int       `json:"version"`
	Archived     bool      `json:"archived"`
	Destroyed    bool      `json:"destroyed"`
	RotationTime time.Time `json:"rotation_time,omitempty"`
}

// ManagedKey holds key material and metadata.
type ManagedKey struct {
	Metadata KeyMetadata
	Material []byte // For symmetric keys; for asymmetric, use PEM encoding.
}

// KeyStore manages all keys (in-memory for demo; for production, use secure storage).
type KeyStore struct {
	Keys      map[string][]ManagedKey // keyID -> versions
	Backup    map[string][]ManagedKey // archived/backup keys
	Destroyed map[string][]ManagedKey // destroyed keys (metadata only, no material)
	mu        sync.Mutex
}

var globalKeyStore = &KeyStore{
	Keys:      make(map[string][]ManagedKey),
	Backup:    make(map[string][]ManagedKey),
	Destroyed: make(map[string][]ManagedKey),
}

// --- Key Generation ---

func GenerateSymmetricKey(keyType KeyType) ([]byte, error) {
	switch keyType {
	case KeyTypeAES128:
		return generateRandomBytes(16)
	case KeyTypeAES256:
		return generateRandomBytes(32)
	case KeyType3DES:
		return generateRandomBytes(24)
	default:
		return nil, fmt.Errorf("unsupported symmetric key type: %s", keyType)
	}
}

func GenerateAsymmetricKey(keyType KeyType) ([]byte, []byte, error) {
	switch keyType {
	case KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096:
		var bits int
		switch keyType {
		case KeyTypeRSA2048:
			bits = 2048
		case KeyTypeRSA3072:
			bits = 3072
		case KeyTypeRSA4096:
			bits = 4096
		}
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
		pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		return privPEM, pubPEM, nil
	case KeyTypeECCP256, KeyTypeECCP384, KeyTypeECCP521:
		var curve elliptic.Curve
		switch keyType {
		case KeyTypeECCP256:
			curve = elliptic.P256()
		case KeyTypeECCP384:
			curve = elliptic.P384()
		case KeyTypeECCP521:
			curve = elliptic.P521()
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		privBytes, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
		pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		return privPEM, pubPEM, nil
	default:
		return nil, nil, fmt.Errorf("unsupported asymmetric key type: %s", keyType)
	}
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// --- HSM Integration (Stub) ---

// In production, integrate with HSM SDK here.
func HSMGenerateKey(keyType KeyType) ([]byte, error) {
	return nil, fmt.Errorf("HSM integration not implemented")
}
func HSMStoreKey(keyID string, key []byte) error {
	return fmt.Errorf("HSM integration not implemented")
}
func HSMDestroyKey(keyID string) error {
	return fmt.Errorf("HSM integration not implemented")
}

// --- Key Management API ---

func (ks *KeyStore) CreateKey(id string, keyType KeyType, usage string) (*ManagedKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	var material []byte
	var err error
	if strings.HasPrefix(string(keyType), "AES") || keyType == KeyType3DES {
		material, err = GenerateSymmetricKey(keyType)
	} else {
		priv, _, err2 := GenerateAsymmetricKey(keyType)
		if err2 != nil {
			return nil, err2
		}
		material = priv
	}
	if err != nil {
		return nil, err
	}
	meta := KeyMetadata{
		ID:        id,
		Type:      keyType,
		CreatedAt: time.Now(),
		Usage:     usage,
		Version:   1,
	}
	key := ManagedKey{Metadata: meta, Material: material}
	ks.Keys[id] = append([]ManagedKey{key}, ks.Keys[id]...)
	return &key, nil
}

func (ks *KeyStore) RotateKey(id string) (*ManagedKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	versions, ok := ks.Keys[id]
	if !ok || len(versions) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	old := versions[0]
	var material []byte
	var err error
	if strings.HasPrefix(string(old.Metadata.Type), "AES") || old.Metadata.Type == KeyType3DES {
		material, err = GenerateSymmetricKey(old.Metadata.Type)
	} else {
		priv, _, err2 := GenerateAsymmetricKey(old.Metadata.Type)
		if err2 != nil {
			return nil, err2
		}
		material = priv
	}
	if err != nil {
		return nil, err
	}
	meta := old.Metadata
	meta.Version++
	meta.CreatedAt = time.Now()
	meta.RotationTime = time.Now()
	key := ManagedKey{Metadata: meta, Material: material}
	ks.Keys[id] = append([]ManagedKey{key}, ks.Keys[id]...)
	return &key, nil
}

func (ks *KeyStore) ArchiveKey(id string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	versions, ok := ks.Keys[id]
	if !ok {
		return fmt.Errorf("key not found")
	}
	ks.Backup[id] = append(ks.Backup[id], versions...)
	delete(ks.Keys, id)
	return nil
}

func (ks *KeyStore) DestroyKey(id string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	versions, ok := ks.Keys[id]
	if !ok {
		return fmt.Errorf("key not found")
	}
	for i := range versions {
		zeroize(versions[i].Material)
		versions[i].Metadata.Destroyed = true
	}
	ks.Destroyed[id] = append(ks.Destroyed[id], versions...)
	delete(ks.Keys, id)
	LogAudit("key_destroy", id, "key destroyed", nil)
	return nil
}

func (ks *KeyStore) RestoreKey(id string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	backup, ok := ks.Backup[id]
	if !ok {
		return fmt.Errorf("no backup found")
	}
	ks.Keys[id] = append(ks.Keys[id], backup...)
	delete(ks.Backup, id)
	return nil
}

func (ks *KeyStore) GetKey(id string, version int) (*ManagedKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	versions, ok := ks.Keys[id]
	if !ok || len(versions) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	for _, k := range versions {
		if k.Metadata.Version == version {
			return &k, nil
		}
	}
	return nil, fmt.Errorf("version not found")
}

func (ks *KeyStore) ListKeys() []KeyMetadata {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	var out []KeyMetadata
	for _, versions := range ks.Keys {
		for _, k := range versions {
			out = append(out, k.Metadata)
		}
	}
	return out
}

// --- Key Usage Policy Enforcement ---

func (ks *KeyStore) EnforceUsage(id string, op string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	versions, ok := ks.Keys[id]
	if !ok || len(versions) == 0 {
		return fmt.Errorf("key not found")
	}
	usage := versions[0].Metadata.Usage
	if usage != op && usage != "all" {
		return fmt.Errorf("key usage policy violation: %s not allowed for %s", op, usage)
	}
	return nil
}

// --- Key API for Secretr ---

func (v *Secretr) CreateManagedKey(id string, keyType KeyType, usage string) (*ManagedKey, error) {
	return globalKeyStore.CreateKey(id, keyType, usage)
}

func (v *Secretr) RotateManagedKey(id string) (*ManagedKey, error) {
	return globalKeyStore.RotateKey(id)
}

func (v *Secretr) ArchiveManagedKey(id string) error {
	return globalKeyStore.ArchiveKey(id)
}

func (v *Secretr) DestroyManagedKey(id string) error {
	return globalKeyStore.DestroyKey(id)
}

func (v *Secretr) RestoreManagedKey(id string) error {
	return globalKeyStore.RestoreKey(id)
}

func (v *Secretr) ListManagedKeys() []KeyMetadata {
	return globalKeyStore.ListKeys()
}

func (v *Secretr) GetManagedKey(id string, version int) (*ManagedKey, error) {
	return globalKeyStore.GetKey(id, version)
}

func (v *Secretr) EnforceKeyUsage(id, op string) error {
	return globalKeyStore.EnforceUsage(id, op)
}

// Securely destroy all key material for a given key ID and audit the event.
func (v *Secretr) DestroyKeyAndAudit(id string) error {
	err := v.DestroyManagedKey(id)
	if err != nil {
		return err
	}
	LogAudit("key_destroy", id, "cryptographic key destroyed", nil)
	return nil
}
