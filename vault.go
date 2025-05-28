package secretr

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/oarkflow/clipboard"
)

var (
	secretrDir     = os.Getenv("SECRETR_DIR")
	defaultSecretr *Secretr
	fingerprint    string
)

const (
	storageFile       = "store.vlt"
	authCacheDuration = time.Minute
	saltSize          = 16
)

// initStorage initializes the secretr storage directory.
func initStorage() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("Error getting home directory: %v", err)
	}
	if secretrDir == "" {
		secretrDir = filepath.Join(homeDir, ".secretr")
	}
	if _, err := os.Stat(secretrDir); os.IsNotExist(err) {
		err = os.MkdirAll(secretrDir, 0700)
		if err != nil {
			return fmt.Errorf("Error creating .secretr directory: %v", err)
		}
	}
	return nil
}

type Persist struct {
	Data              map[string]any    `json:"data"`
	ResetAttempts     int               `json:"resetAttempts"`
	NormalAttempts    int               `json:"normalAttempts"`
	BannedUntil       time.Time         `json:"bannedUntil"`
	LockedForever     bool              `json:"lockedForever"`
	EnableReset       bool              `json:"enableReset"`
	ResetCode         string            `json:"resetCode"`
	DeviceFingerprint string            `json:"deviceFingerprint"`
	SSHKeys           map[string]string `json:"sshKeys"`
	Certificates      map[string]string `json:"certificates"`
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
		SSHKeys:           make(map[string]string),
		Certificates:      make(map[string]string),
	}
}

// Secretr represents the secret storage with encryption, reset and rate limiting.
type Secretr struct {
	store     Persist
	masterKey []byte
	salt      []byte
	authedAt  time.Time
	mu        sync.Mutex
	cipherGCM cipher.AEAD
	nonceSize int
	// Added field for prompt override:
	promptFunc func() error
}

// New creates a new Secretr instance.
func New() *Secretr {
	return &Secretr{
		store: NewPersist(),
	}
}

// Added method to set GUI prompt override.
func (v *Secretr) SetPrompt(prompt func() error) {
	v.promptFunc = prompt
}

// InitCipher initializes the AES-GCM cipher with the provided password and salt.
func (v *Secretr) InitCipher(pw []byte, salt []byte) {
	if salt == nil {
		salt = make([]byte, saltSize)
		rand.Read(salt)
	}
	v.salt = salt
	key := DeriveKey(pw, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("failed to create GCM: %v", err)
	}
	v.masterKey = key
	v.cipherGCM = gcm
	v.nonceSize = gcm.NonceSize()
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
	fingerprint, err = GetDeviceFingerPrint()
	if err != nil {
		log.Fatalf("failed to get device fingerprint: %v", err)
	}
	if err := initStorage(); err != nil {
		log.Fatal(err)
	}
	defaultSecretr = New()
}

func Set(key string, value any) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Set(key, value)
}

func Copy(key string) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Copy(key)
}

func Delete(key string) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Delete(key)
}

// Get retrieves the value associated with the provided key.
func Get(key string) (string, error) {
	if defaultSecretr == nil {
		return "", fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Get(key)
}

func Unmarshal(key string, dest any) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Unmarshal(key, dest)
}

// LoadFromEnv loads environment variables into the secretr.
func LoadFromEnv() {
	if defaultSecretr == nil {
		log.Fatal("secretr not initialized")
	}
	defaultSecretr.LoadFromEnv()
}

// FilePath returns the path of the secretr storage file.
func FilePath() string {
	return filepath.Join(secretrDir, storageFile)
}

// promptMaster prompts for the MasterKey and initializes the secretr accordingly.
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
							binary.Read(rand.Reader, binary.BigEndian, &num)
							v.store.ResetCode = fmt.Sprintf("%06d", num%1000000)
							sendResetEmail(v.store.ResetCode)
							fmt.Println("Too many attempts. Reset code has been sent to your email.")
						}
						continue
					} else {
						v.store.BannedUntil = time.Now().Add(10 * time.Minute)
						fmt.Printf("Too many attempts. Secretr is banned until %v.\n", v.store.BannedUntil.Format(time.DateTime))
						v.Save()
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
	if emailService == "smtp" {
		smtpServer := os.Getenv("SECRETR_SMTP_SERVER")
		smtpPort := os.Getenv("SECRETR_SMTP_PORT")
		smtpUser := os.Getenv("SECRETR_SMTP_USER")
		smtpPass := os.Getenv("SECRETR_SMTP_PASS")
		if smtpServer == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" || resetEmail == "" {
			fmt.Println("SMTP details missing. Reset code:", code)
			return
		}
		subject := "Reset Code"
		message := "Subject: " + subject + "\n\nYour reset code is: " + code
		auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpServer)
		addr := smtpServer + ":" + smtpPort
		err := smtp.SendMail(addr, auth, smtpUser, []string{resetEmail}, []byte(message))
		if err != nil {
			fmt.Println("Failed to send reset code via SMTP:", err)
		} else {
			fmt.Println("Reset code sent via SMTP.")
		}
	} else if emailService == "ses" {
		// Placeholder for AWS SES integration; implement AWS SES sending logic here.
		fmt.Println("AWS SES integration placeholder. Reset code:", code)
	} else {
		fmt.Printf("Sending reset code %s to user's email...\n", code)
	}
}

// forceReset forces the reset flow using a reset code.
func (v *Secretr) forceReset() error {
	if v.store.ResetCode == "" {
		var num int64
		binary.Read(rand.Reader, binary.BigEndian, &num)
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
				return err
			}
			if string(new1) != string(new2) {
				fmt.Println("MasterKeys do not match. Try again.")
				continue
			}
			v.InitCipher(new1, nil)
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
		return fmt.Errorf("Invalid MasterKey or corrupt secretr file: %v", err)
	}

	var persist Persist
	if err := json.Unmarshal(plain, &persist); err != nil {
		return err
	}
	v.store = persist
	if v.store.DeviceFingerprint != "" {
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
		var current any = node
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
		v.store.SSHKeys = make(map[string]string)
	}
	if v.store.Certificates == nil {
		v.store.Certificates = make(map[string]string)
	}
}

// Execute runs the secretr CLI loop.
func Execute() {
	secretr := New()
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

// cliLoop handles the interactive CLI commands.
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
				secretr.Save()
				fmt.Println("Exiting secretr CLI.")
				clipboard.WriteAll("")
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
		}
		if len(parts) < 2 {
			fmt.Println("usage: set|get|delete|copy|env|enrich|list|ssh-key|certificate|sign|verify|hash key [value]")
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
			if len(parts) < 3 || parts[1] != "generate" {
				fmt.Println("usage: ssh-key generate <name>")
				continue
			}
			name := parts[2]
			if err := secretr.GenerateSSHKey(name); err != nil {
				fmt.Println("error:", err)
			} else {
				fmt.Println("SSH Key generated successfully:", name)
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
	privateKey, publicKey, err := generateSSHKeyPair()
	if err != nil {
		return err
	}
	v.store.SSHKeys[name] = privateKey + "\n" + publicKey
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

// generateSSHKeyPair generates an SSH key pair (private and public keys).
func generateSSHKeyPair() (string, string, error) {
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
