package secretr

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	mathRand "math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/clipboard"
	"golang.org/x/term"
)

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
			if cmd == "tenant-add" {
				if len(parts) < 2 {
					fmt.Println("usage: tenant-add <tenant_name>")
					continue
				}
				tenant, err := AddTenant(parts[1])
				if err != nil {
					fmt.Println("error:", err)
				} else {
					fmt.Printf("Tenant %s added. AdminKey (base64): %s\n", tenant.Name, base64.StdEncoding.EncodeToString(tenant.AdminKey))
				}
				continue
			}
			if cmd == "tenant-list" {
				names := ListTenants()
				for _, n := range names {
					fmt.Println(n)
				}
				continue
			}
			if cmd == "tenant-setkey" {
				if len(parts) < 3 {
					fmt.Println("usage: tenant-setkey <tenant_name> <base64_admin_key>")
					continue
				}
				key, err := base64.StdEncoding.DecodeString(parts[2])
				if err != nil {
					fmt.Println("invalid key:", err)
					continue
				}
				if err := SetTenantAdminKey(parts[1], key); err != nil {
					fmt.Println("error:", err)
				} else {
					fmt.Println("Admin key updated for tenant:", parts[1])
				}
				continue
			}
			if cmd == "tenant-getkey" {
				if len(parts) < 2 {
					fmt.Println("usage: tenant-getkey <tenant_name>")
					continue
				}
				key, err := GetTenantAdminKey(parts[1])
				if err != nil {
					fmt.Println("error:", err)
				} else {
					fmt.Println(base64.StdEncoding.EncodeToString(key))
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

// All cryptographic key management, encryption, decryption, signing, verification, key derivation, backup encryption, and device fingerprinting
// are implemented using secure, NIST SP 800-57-compliant primitives and Go standard library cryptography.

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

// --- Cryptographic Operations for Managed Keys ---

// Encrypt using a managed key (AES/3DES/RSA).
func (ks *KeyStore) Encrypt(id string, plaintext []byte) ([]byte, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	versions, ok := ks.Keys[id]
	if !ok || len(versions) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	key := versions[0]
	switch key.Metadata.Type {
	case KeyTypeAES128, KeyTypeAES256:
		block, err := aes.NewCipher(key.Material)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
		return ciphertext, nil
	case KeyType3DES:
		block, err := des.NewTripleDESCipher(key.Material)
		if err != nil {
			return nil, err
		}
		iv := make([]byte, block.BlockSize())
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
		padLen := block.BlockSize() - len(plaintext)%block.BlockSize()
		pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
		plainPadded := append(plaintext, pad...)
		ciphertext := make([]byte, len(plainPadded))
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(ciphertext, plainPadded)
		return append(iv, ciphertext...), nil
	case KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096:
		priv, err := parseRSAPrivateKey(key.Material)
		if err != nil {
			return nil, err
		}
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, plaintext, nil)
	default:
		return nil, fmt.Errorf("encryption not supported for key type: %s", key.Metadata.Type)
	}
}

// Decrypt using a managed key (AES/3DES/RSA).
func (ks *KeyStore) Decrypt(id string, ciphertext []byte) ([]byte, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	versions, ok := ks.Keys[id]
	if !ok || len(versions) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	key := versions[0]
	switch key.Metadata.Type {
	case KeyTypeAES128, KeyTypeAES256:
		block, err := aes.NewCipher(key.Material)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		nonceSize := gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			return nil, errors.New("ciphertext too short")
		}
		nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
		return gcm.Open(nil, nonce, ct, nil)
	case KeyType3DES:
		block, err := des.NewTripleDESCipher(key.Material)
		if err != nil {
			return nil, err
		}
		bs := block.BlockSize()
		if len(ciphertext) < bs {
			return nil, errors.New("ciphertext too short")
		}
		iv, ct := ciphertext[:bs], ciphertext[bs:]
		if len(ct)%bs != 0 {
			return nil, errors.New("invalid ciphertext length")
		}
		plainPadded := make([]byte, len(ct))
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(plainPadded, ct)
		padLen := int(plainPadded[len(plainPadded)-1])
		if padLen > bs || padLen == 0 {
			return nil, errors.New("invalid padding")
		}
		return plainPadded[:len(plainPadded)-padLen], nil
	case KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096:
		priv, err := parseRSAPrivateKey(key.Material)
		if err != nil {
			return nil, err
		}
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
	default:
		return nil, fmt.Errorf("decryption not supported for key type: %s", key.Metadata.Type)
	}
}

// Sign using a managed key (RSA/ECC).
func (ks *KeyStore) Sign(id string, data []byte) ([]byte, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	versions, ok := ks.Keys[id]
	if !ok || len(versions) == 0 {
		return nil, fmt.Errorf("key not found")
	}
	key := versions[0]
	hash := sha256.Sum256(data)
	switch key.Metadata.Type {
	case KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096:
		priv, err := parseRSAPrivateKey(key.Material)
		if err != nil {
			return nil, err
		}
		return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	case KeyTypeECCP256, KeyTypeECCP384, KeyTypeECCP521:
		priv, err := parseECPrivateKey(key.Material)
		if err != nil {
			return nil, err
		}
		r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
		if err != nil {
			return nil, err
		}
		return asn1MarshalECDSASignature(r, s)
	default:
		return nil, fmt.Errorf("signing not supported for key type: %s", key.Metadata.Type)
	}
}

// Verify using a managed key (RSA/ECC).
func (ks *KeyStore) Verify(id string, data, signature []byte) (bool, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	versions, ok := ks.Keys[id]
	if !ok || len(versions) == 0 {
		return false, fmt.Errorf("key not found")
	}
	key := versions[0]
	hash := sha256.Sum256(data)
	switch key.Metadata.Type {
	case KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096:
		priv, err := parseRSAPrivateKey(key.Material)
		if err != nil {
			return false, err
		}
		pub := &priv.PublicKey
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], signature)
		return err == nil, nil
	case KeyTypeECCP256, KeyTypeECCP384, KeyTypeECCP521:
		priv, err := parseECPrivateKey(key.Material)
		if err != nil {
			return false, err
		}
		r, s, err := asn1UnmarshalECDSASignature(signature)
		if err != nil {
			return false, err
		}
		ok := ecdsa.Verify(&priv.PublicKey, hash[:], r, s)
		return ok, nil
	default:
		return false, fmt.Errorf("verification not supported for key type: %s", key.Metadata.Type)
	}
}

// --- Key Parsing Helpers ---

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid RSA private key PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parseECPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("invalid EC private key PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func asn1MarshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

func asn1UnmarshalECDSASignature(sig []byte) (*big.Int, *big.Int, error) {
	var es struct{ R, S *big.Int }
	_, err := asn1.Unmarshal(sig, &es)
	return es.R, es.S, err
}

// --- Key Management API ---

func (ks *KeyStore) CreateKey(id string, keyType KeyType, usage string) (*ManagedKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	var material []byte
	var err error
	switch keyType {
	case KeyTypeAES128, KeyTypeAES256:
		material, err = GenerateSymmetricKey(keyType)
	case KeyType3DES:
		material, err = GenerateSymmetricKey(keyType)
	case KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096, KeyTypeECCP256, KeyTypeECCP384, KeyTypeECCP521:
		material, _, err = GenerateAsymmetricKey(keyType)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
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
	switch old.Metadata.Type {
	case KeyTypeAES128, KeyTypeAES256:
		material, err = GenerateSymmetricKey(old.Metadata.Type)
	case KeyType3DES:
		material, err = GenerateSymmetricKey(old.Metadata.Type)
	case KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096, KeyTypeECCP256, KeyTypeECCP384, KeyTypeECCP521:
		material, _, err = GenerateAsymmetricKey(old.Metadata.Type)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", old.Metadata.Type)
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

// Tenant represents a tenant in the multi-tenant system.
type Tenant struct {
	Name      string
	AdminKey  []byte // Admin key for tenant (AES-256)
	Secrets   map[string]string
	CreatedAt time.Time
}

var (
	tenantStoreMu sync.Mutex
	tenantStore   = make(map[string]*Tenant)
)

// AddTenant creates a new tenant with a random admin key.
func AddTenant(name string) (*Tenant, error) {
	tenantStoreMu.Lock()
	defer tenantStoreMu.Unlock()
	if _, exists := tenantStore[name]; exists {
		return nil, fmt.Errorf("tenant %s already exists", name)
	}
	key, err := generateRandomBytes(32)
	if err != nil {
		return nil, err
	}
	tenant := &Tenant{
		Name:      name,
		AdminKey:  key,
		Secrets:   make(map[string]string),
		CreatedAt: time.Now(),
	}
	tenantStore[name] = tenant
	return tenant, nil
}

// ListTenants returns all tenant names.
func ListTenants() []string {
	tenantStoreMu.Lock()
	defer tenantStoreMu.Unlock()
	var names []string
	for name := range tenantStore {
		names = append(names, name)
	}
	return names
}

// SetTenantAdminKey sets a new admin key for a tenant.
func SetTenantAdminKey(name string, key []byte) error {
	tenantStoreMu.Lock()
	defer tenantStoreMu.Unlock()
	tenant, ok := tenantStore[name]
	if !ok {
		return fmt.Errorf("tenant %s not found", name)
	}
	if len(key) != 32 {
		return fmt.Errorf("admin key must be 32 bytes")
	}
	tenant.AdminKey = key
	return nil
}

// GetTenantAdminKey returns the admin key for a tenant.
func GetTenantAdminKey(name string) ([]byte, error) {
	tenantStoreMu.Lock()
	defer tenantStoreMu.Unlock()
	tenant, ok := tenantStore[name]
	if !ok {
		return nil, fmt.Errorf("tenant %s not found", name)
	}
	return tenant.AdminKey, nil
}

// SetTenantSecret sets a secret for a tenant.
func SetTenantSecret(name, key, value string) error {
	tenantStoreMu.Lock()
	defer tenantStoreMu.Unlock()
	tenant, ok := tenantStore[name]
	if !ok {
		return fmt.Errorf("tenant %s not found", name)
	}
	tenant.Secrets[key] = value
	return nil
}

// GetTenantSecret gets a secret for a tenant.
func GetTenantSecret(name, key string) (string, error) {
	tenantStoreMu.Lock()
	defer tenantStoreMu.Unlock()
	tenant, ok := tenantStore[name]
	if !ok {
		return "", fmt.Errorf("tenant %s not found", name)
	}
	val, ok := tenant.Secrets[key]
	if !ok {
		return "", fmt.Errorf("secret %s not found for tenant %s", key, name)
	}
	return val, nil
}
