package vault

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/oarkflow/clipboard"
)

var (
	vaultDir     = os.Getenv("VAULT_DIR")
	defaultVault *Vault
)

const (
	storageFile       = "store.vlt"
	authCacheDuration = time.Minute
	saltSize          = 16
)

// initStorage initializes the vault storage directory.
func initStorage() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("Error getting home directory: %v", err)
	}
	if vaultDir == "" {
		vaultDir = filepath.Join(homeDir, ".vault")
	}
	if _, err := os.Stat(vaultDir); os.IsNotExist(err) {
		err = os.MkdirAll(vaultDir, 0700)
		if err != nil {
			return fmt.Errorf("Error creating .vault directory: %v", err)
		}
	}
	return nil
}

// Vault represents the secret storage with encryption, reset and rate limiting.
type Vault struct {
	data           map[string]any
	masterKey      []byte
	Salt           []byte
	authedAt       time.Time
	mu             sync.Mutex
	cipherGCM      cipher.AEAD
	nonceSize      int
	resetAttempts  int
	normalAttempts int
	bannedUntil    time.Time
	lockedForever  bool
	EnableReset    bool
	ResetCode      string
}

// initCipher initializes the AES-GCM cipher with the provided password and salt.
func (v *Vault) initCipher(pw []byte, salt []byte) {
	if salt == nil {
		salt = make([]byte, saltSize)
		rand.Read(salt)
	}
	v.Salt = salt
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

// init initializes the vault by setting up storage.
func init() {
	if err := initStorage(); err != nil {
		log.Fatal(err)
	}
	defaultVault = New()
}

// New creates a new Vault instance.
func New() *Vault {
	return &Vault{data: make(map[string]any)}
}

// Get retrieves the value associated with the provided key.
func Get(key string) (string, error) {
	if defaultVault == nil {
		return "", fmt.Errorf("vault not initialized")
	}
	return defaultVault.Get(key)
}

// LoadFromEnv loads environment variables into the vault.
func LoadFromEnv() {
	if defaultVault == nil {
		log.Fatal("vault not initialized")
	}
	defaultVault.LoadFromEnv()
}

// FilePath returns the path of the vault storage file.
func FilePath() string {
	return filepath.Join(vaultDir, storageFile)
}

// promptMaster prompts for the MasterKey and initializes the vault accordingly.
func (v *Vault) promptMaster() error {

	if time.Since(v.authedAt) < authCacheDuration && v.cipherGCM != nil {
		return nil
	}

	if v.EnableReset && ((!v.bannedUntil.IsZero() && time.Now().Before(v.bannedUntil)) || v.lockedForever) {
		if err := v.forceReset(); err != nil {
			return err
		}
		v.authedAt = time.Now()
		return nil
	}

	if v.lockedForever {
		return fmt.Errorf("vault locked permanently")
	}
	if !v.bannedUntil.IsZero() && time.Now().Before(v.bannedUntil) {
		return fmt.Errorf("vault banned until %v", v.bannedUntil)
	}

	if _, err := os.Stat(FilePath()); os.IsNotExist(err) {
		for {
			fmt.Println("Vault database not found. Setting up a new vault.")
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

			v.initCipher(pw1, nil)

			fmt.Print("Enable Reset Password? (y/N): ")
			respReader := bufio.NewReader(os.Stdin)
			resp, _ := respReader.ReadString('\n')
			resp = strings.TrimSpace(strings.ToLower(resp))
			if resp == "y" {
				v.EnableReset = true
			} else {
				v.EnableReset = false
			}
			if err := v.save(); err != nil {
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
			return fmt.Errorf("corrupt vault file")
		}
		salt := decoded[:saltSize]

		for {
			fmt.Print("Enter MasterKey: ")
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return err
			}
			v.initCipher(pw, salt)
			if err := v.load(); err != nil {
				fmt.Println("Incorrect MasterKey.")
				v.normalAttempts++
				if v.normalAttempts >= 3 {
					if v.EnableReset {
						if v.ResetCode == "" {
							var num int64
							binary.Read(rand.Reader, binary.BigEndian, &num)
							v.ResetCode = fmt.Sprintf("%06d", num%1000000)
							sendResetEmail(v.ResetCode)
							fmt.Println("Too many attempts. Reset code has been sent to your email.")
						}
						continue
					} else {
						v.bannedUntil = time.Now().Add(10 * time.Minute)
						fmt.Printf("Too many attempts. Vault is banned until %v.\n", v.bannedUntil.Format(time.DateTime))
						v.save()
						return fmt.Errorf("failed to authenticate: vault banned until %v", v.bannedUntil)
					}
				}
				continue
			}
			v.authedAt = time.Now()
			v.normalAttempts = 0
			return nil
		}
	}
}

// sendResetEmail simulates sending a reset code via email.
func sendResetEmail(code string) {

	fmt.Printf("Sending reset code %s to user's email...\n", code)
}

// forceReset forces the reset flow using a reset code.
func (v *Vault) forceReset() error {

	if v.ResetCode == "" {
		var num int64
		binary.Read(rand.Reader, binary.BigEndian, &num)
		v.ResetCode = fmt.Sprintf("%06d", num%1000000)
		sendResetEmail(v.ResetCode)
		fmt.Println("Vault is banned/locked. Reset code has been sent to your email.")
	}

	for {
		fmt.Print("Enter reset code: ")
		resetReader := bufio.NewReader(os.Stdin)
		input, _ := resetReader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != v.ResetCode {
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
			v.initCipher(new1, nil)

			v.resetAttempts = 0
			v.normalAttempts = 0
			v.bannedUntil = time.Time{}
			v.lockedForever = false
			v.ResetCode = ""
			if err := v.save(); err != nil {
				return err
			}
			fmt.Println("MasterKey has been reset successfully.")
			return nil
		}
	}
}

// load decrypts and loads the vault data from disk.
func (v *Vault) load() error {
	enc, err := os.ReadFile(FilePath())
	if err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(string(enc))
	if err != nil {
		return err
	}
	if len(decoded) < saltSize+v.nonceSize {
		return fmt.Errorf("corrupt vault file")
	}

	data := decoded[saltSize:]
	nonce := data[:v.nonceSize]
	ciphertext := data[v.nonceSize:]
	plain, err := v.cipherGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	var persist struct {
		Data           map[string]any `json:"data"`
		ResetAttempts  int            `json:"resetAttempts"`
		NormalAttempts int            `json:"normalAttempts"`
		BannedUntil    time.Time      `json:"bannedUntil"`
		LockedForever  bool           `json:"lockedForever"`
		EnableReset    bool           `json:"enableReset"`
		ResetCode      string         `json:"resetCode"`
	}
	if err := json.Unmarshal(plain, &persist); err != nil {
		return err
	}

	v.data = persist.Data
	v.resetAttempts = persist.ResetAttempts
	v.normalAttempts = persist.NormalAttempts
	v.bannedUntil = persist.BannedUntil
	v.lockedForever = persist.LockedForever
	v.EnableReset = persist.EnableReset
	v.ResetCode = persist.ResetCode
	if !v.bannedUntil.IsZero() && time.Now().Before(v.bannedUntil) {
		return fmt.Errorf("vault banned until %v", v.bannedUntil.Format(time.DateTime))
	}
	return nil
}

// save encrypts and saves the vault data to disk.
func (v *Vault) save() error {

	persist := struct {
		Data           map[string]any `json:"data"`
		ResetAttempts  int            `json:"resetAttempts"`
		NormalAttempts int            `json:"normalAttempts"`
		BannedUntil    time.Time      `json:"bannedUntil"`
		LockedForever  bool           `json:"lockedForever"`
		EnableReset    bool           `json:"enableReset"`
		ResetCode      string         `json:"resetCode"`
	}{
		Data:           v.data,
		ResetAttempts:  v.resetAttempts,
		NormalAttempts: v.normalAttempts,
		BannedUntil:    v.bannedUntil,
		LockedForever:  v.lockedForever,
		EnableReset:    v.EnableReset,
		ResetCode:      v.ResetCode,
	}
	plain, err := json.Marshal(persist)
	if err != nil {
		return err
	}
	nonce := make([]byte, v.nonceSize)
	_, _ = io.ReadFull(rand.Reader, nonce)
	ciphertext := v.cipherGCM.Seal(nonce, nonce, plain, nil)

	final := append(v.Salt, ciphertext...)
	enc := base64.StdEncoding.EncodeToString(final)
	return os.WriteFile(FilePath(), []byte(enc), 0600)
}

// Set assigns a secret value to a key.
func (v *Vault) Set(key, value string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	if err := v.promptMaster(); err != nil {
		return err
	}

	if strings.Contains(key, ".") {
		parts := strings.Split(key, ".")
		base := parts[0]
		subkeys := parts[1:]
		var node map[string]any
		if existing, ok := v.data[base]; ok {
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
		v.data[base] = node
	} else {
		trimmed := strings.TrimSpace(value)

		if strings.HasPrefix(trimmed, "{") {
			var parsed map[string]any
			if err := json.Unmarshal([]byte(value), &parsed); err == nil {
				v.data[key] = parsed
			} else {
				v.data[key] = value
			}
		} else {
			v.data[key] = value
		}
	}

	err := v.save()
	if err == nil {
		LogAudit("set", key, "value set", v.masterKey)
	}
	return err
}

// Get returns the decrypted secret for a given key.
func (v *Vault) Get(key string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	if err := v.promptMaster(); err != nil {
		return "", err
	}
	if strings.Contains(key, ".") {
		parts := strings.Split(key, ".")
		base := parts[0]
		subkeys := parts[1:]
		node, ok := v.data[base]
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
		value, ok := v.data[key]
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

// Delete removes a secret from the vault.
func (v *Vault) Delete(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.initData()
	if err := v.promptMaster(); err != nil {
		return err
	}
	if strings.Contains(key, ".") {
		parts := strings.Split(key, ".")
		base := parts[0]
		subkeys := parts[1:]
		node, ok := v.data[base]
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
			delete(v.data, base)
		} else {
			v.data[base] = current
		}
	} else {
		delete(v.data, key)
	}

	err := v.save()
	if err == nil {
		LogAudit("delete", key, "deleted", v.masterKey)
	}
	return err
}

// Copy copies a secret to the clipboard.
func (v *Vault) Copy(key string) error {
	val, err := v.Get(key)
	if err != nil {
		return err
	}
	return clipboard.WriteAll(val)
}

// Env sets a secret as an environment variable.
func (v *Vault) Env(key string) error {

	secret, err := v.Get(key)
	if err != nil {
		return err
	}
	return os.Setenv(key, secret)
}

// EnrichEnv sets all vault keys as environment variables.
func (v *Vault) EnrichEnv() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, val := range v.data {
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

// initData initializes the vault data map if it's nil.
func (v *Vault) initData() {
	if v.data == nil {
		v.data = make(map[string]any)
	}
}

// Execute runs the vault CLI loop.
func Execute() {
	vault := New()
	err := vault.promptMaster()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	cliLoop(vault)
}

// LoadFromEnv loads environment variables into the vault.
func (v *Vault) LoadFromEnv() {
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
func cliLoop(vault *Vault) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("vault> ")
		if !scanner.Scan() {
			break
		}
		parts := strings.Fields(scanner.Text())
		if len(parts) > 0 {
			cmd := strings.ToLower(parts[0])
			if cmd == "exit" || cmd == "quit" {
				vault.save()
				fmt.Println("Exiting vault CLI.")
				clipboard.WriteAll("")
				return
			}
			if cmd == "list" {
				keys := vault.List()
				for _, k := range keys {
					fmt.Println(k)
				}
				continue
			}
			if cmd == "enrich" {
				if err := vault.EnrichEnv(); err != nil {
					fmt.Println("error:", err)
				} else {
					fmt.Println("Vault secrets enriched into environment variables.")
				}
				continue
			}
		}
		if len(parts) < 2 {
			fmt.Println("usage: set|get|delete|copy|env|enrich|list key [value]")
			continue
		}
		op, key := strings.ToLower(parts[0]), parts[1]
		switch op {
		case "set", "update":
			fmt.Print("Enter secret: ")
			pw, _ := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err := vault.Set(key, string(pw)); err != nil {
				fmt.Println("error:", err)
			}
		case "get":
			val, err := vault.Get(key)
			if err != nil {
				fmt.Println("error:", err)
			} else {
				fmt.Println(val)
			}
		case "delete":
			if err := vault.Delete(key); err != nil {
				fmt.Println("error:", err)
			}
		case "env":

			if err := vault.Env(key); err != nil {
				fmt.Println("error:", err)
			} else {
				fmt.Println("Environment variable set:", key)
			}
		case "load-env":
			vault.LoadFromEnv()
		case "copy":
			if err := vault.Copy(key); err != nil {
				fmt.Println("error:", err)
			} else {
				fmt.Println("secret copied to clipboard")
			}
		case "exit":
			return
		default:
			fmt.Println("unknown command")
		}
	}
}

// List returns a flattened list of keys stored in the vault.
func (v *Vault) List() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	var keys []string
	flattenKeys(v.data, "", &keys)
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
