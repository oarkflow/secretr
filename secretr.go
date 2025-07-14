package secretr

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
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

// FileMetadata represents information about stored files
type FileMetadata struct {
	FileName    string            `json:"fileName"`
	Size        int64             `json:"size"`
	ContentType string            `json:"contentType"`
	CreatedAt   time.Time         `json:"createdAt"`
	ModifiedAt  time.Time         `json:"modifiedAt"`
	Tags        []string          `json:"tags,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
	CheckSum    string            `json:"checkSum"` // Store file hash for integrity
}

func (m FileMetadata) IsImage() bool {
	return strings.HasPrefix(m.ContentType, "image/")
}

// StoredFile represents an encrypted file with its metadata
type StoredFile struct {
	Metadata  FileMetadata `json:"metadata"`
	Encrypted []byte       `json:"encrypted"` // Encrypted file content
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
	Files             map[string]StoredFile   `json:"files,omitempty"`
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
		Files:             make(map[string]StoredFile),   // initialize Files map
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

func (v *Secretr) Sync() error {
	if v.masterKey == nil {
		return fmt.Errorf("master key not initialized")
	}

	// Load existing data
	if err := v.Load(); err != nil {
		return fmt.Errorf("failed to load existing data: %v", err)
	}

	// Save the current state
	if err := v.Save(); err != nil {
		return fmt.Errorf("failed to save current state: %v", err)
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

// StoreFile encrypts and stores a file in the vault
func (v *Secretr) StoreFile(filePath string, tags []string, properties map[string]string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := v.PromptMaster(); err != nil {
		return err
	}

	// Read file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Calculate checksum
	hash := sha256.Sum256(content)
	checkSum := base64.StdEncoding.EncodeToString(hash[:])

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}

	// Create metadata
	metadata := FileMetadata{
		FileName:    filepath.Base(filePath),
		Size:        fileInfo.Size(),
		ContentType: detectContentType(content, filePath),
		CreatedAt:   time.Now(),
		ModifiedAt:  time.Now(),
		Tags:        tags,
		Properties:  properties,
		CheckSum:    checkSum,
	}

	// Encrypt file content
	nonce := make([]byte, v.nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %v", err)
	}

	encrypted := v.cipherGCM.Seal(nonce, nonce, content, nil)

	// Store the file
	storedFile := StoredFile{
		Metadata:  metadata,
		Encrypted: encrypted,
	}

	// Ensure Files map is initialized
	if v.store.Files == nil {
		v.store.Files = make(map[string]StoredFile)
	}
	v.store.Files[metadata.FileName] = storedFile

	err = v.Save()
	if err == nil {
		LogAudit("store_file", metadata.FileName, "file stored", v.masterKey)
	} else {
		return fmt.Errorf("failed to save file to vault: %v", err)
	}
	return nil
}

// RetrieveFile gets a file from the vault and decrypts it
func (v *Secretr) RetrieveFile(fileName string) ([]byte, FileMetadata, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := v.PromptMaster(); err != nil {
		return nil, FileMetadata{}, err
	}
	if err := v.Load(); err != nil {
		return nil, FileMetadata{}, fmt.Errorf("failed to load vault: %v", err)
	}
	storedFile, exists := v.store.Files[fileName]
	if !exists {
		return nil, FileMetadata{}, fmt.Errorf("file not found: %s", fileName)
	}

	// Extract nonce and ciphertext
	if len(storedFile.Encrypted) < v.nonceSize {
		return nil, FileMetadata{}, fmt.Errorf("corrupt encrypted file")
	}
	nonce := storedFile.Encrypted[:v.nonceSize]
	ciphertext := storedFile.Encrypted[v.nonceSize:]

	// Decrypt
	content, err := v.cipherGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, FileMetadata{}, fmt.Errorf("failed to decrypt file: %v", err)
	}

	return content, storedFile.Metadata, nil
}

// ListFiles returns a list of stored files and their metadata
func (v *Secretr) ListFiles() []FileMetadata {
	var files []FileMetadata
	for _, file := range v.store.Files {
		files = append(files, file.Metadata)
	}
	return files
}

// DeleteFile removes a file from the vault
func (v *Secretr) DeleteFile(fileName string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if err := v.PromptMaster(); err != nil {
		return err
	}

	if _, exists := v.store.Files[fileName]; !exists {
		return fmt.Errorf("file not found: %s", fileName)
	}

	delete(v.store.Files, fileName)

	err := v.Save()
	if err == nil {
		LogAudit("delete_file", fileName, "file deleted", v.masterKey)
	}
	return err
}

// Helper function to detect content type
func detectContentType(content []byte, fileName string) string {
	// Get extension, convert to lowercase for consistency
	ext := strings.ToLower(filepath.Ext(fileName))
	if ext != "" {
		// Use MIME package to get content type from extension
		if mimeType := mime.TypeByExtension(ext); mimeType != "" {
			return mimeType
		}
	}
	// Fallback to http.DetectContentType only if mime type wasn't found
	return http.DetectContentType(content)
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
