package shamir

import (
	"crypto/rand"
	"errors"

	"github.com/oarkflow/secretr/storage"
)

// Precomputed tables for GF(256) arithmetic using the polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
var (
	expTable [512]byte
	logTable [256]byte
)

func init() {
	// initialize exp and log tables
	var x byte = 1
	for i := 0; i < 255; i++ {
		expTable[i] = x
		logTable[x] = byte(i)
		x = gfMulNoLUT(x, 0x03)
	}
	// duplicate for easy reduction
	for i := 255; i < 512; i++ {
		expTable[i] = expTable[i-255]
	}
}

// Add two field elements (XOR)
func add(a, b byte) byte {
	return a ^ b
}

// Subtraction is the same as addition in GF(256)
func sub(a, b byte) byte {
	return a ^ b
}

// Multiply using lookup tables
func mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	s := int(logTable[a]) + int(logTable[b])
	// mod 255
	if s >= 255 {
		s -= 255
	}
	return expTable[s]
}

// gfMulNoLUT is a simple bitwise multiplication used to generate tables
func gfMulNoLUT(a, b byte) byte {
	var p byte
	for b > 0 {
		if (b & 1) != 0 {
			p ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

// Inverse using tables
func inv(a byte) (byte, error) {
	if a == 0 {
		return 0, errors.New("shamir: inverse of zero")
	}
	// 255 - log(a)
	return expTable[255-int(logTable[a])], nil
}

// Split divides a secret byte slice into `n` shares, requiring `t` shares to reconstruct.
// Each share is a byte slice of length len(secret)+1, where the first byte is the share index (1..255).
func Split(secret []byte, t, n int) ([][]byte, error) {
	if t < 2 || t > 255 {
		return nil, errors.New("shamir: threshold must be between 2 and 255")
	}
	if n < t || n > 255 {
		return nil, errors.New("shamir: number of shares must be between threshold and 255")
	}
	// generate coefficients: a_0 = secret byte, a_1..a_{t-1} random
	shares := make([][]byte, n)
	for i := range shares {
		// allocate extra byte for total shares header
		shares[i] = make([]byte, len(secret)+2)
		shares[i][0] = byte(i + 1) // share (chunk) index (x coordinate)
		shares[i][1] = byte(n)     // total shares/chunks
	}
	// for each byte in secret, generate polynomial
	for j := 0; j < len(secret); j++ {
		// random coefficients
		coeffs := make([]byte, t)
		coeffs[0] = secret[j]
		_, err := rand.Read(coeffs[1:])
		if err != nil {
			return nil, err
		}
		// evaluate polynomial at each x
		for i := 0; i < n; i++ {
			x := shares[i][0]
			var y byte = coeffs[0]
			var powX byte = 1
			for k := 1; k < t; k++ {
				powX = mul(powX, x)
				y = add(y, mul(coeffs[k], powX))
			}
			shares[i][j+2] = y // changed offset to +2 for header
		}
	}
	return shares, nil
}

// Combine reconstructs the secret from at least `t` shares.
func Combine(shares [][]byte, t int) ([]byte, error) {
	// Validate that we have at least t shares.
	if len(shares) < t {
		return nil, errors.New("shamir: insufficient shares for threshold")
	}
	if len(shares) > t {
		shares = shares[:t]
	}
	n := t

	// all shares must have same length and valid header
	length := len(shares[0])
	totalSharesHeader := shares[0][1]
	xs := make([]byte, n)
	used := make(map[byte]bool)
	for i, s := range shares {
		if len(s) != length {
			return nil, errors.New("shamir: mismatched share lengths")
		}
		// Validate total shares header consistency
		if s[1] != totalSharesHeader {
			return nil, errors.New("shamir: inconsistent total shares header")
		}
		xi := s[0]
		if xi == 0 {
			return nil, errors.New("shamir: share index cannot be zero")
		}
		if used[xi] {
			return nil, errors.New("shamir: duplicate share indices detected")
		}
		used[xi] = true
		xs[i] = xi
	}
	// Precompute product of all x coordinates: productAll = ∏ xi
	productAll := byte(1)
	for _, xi := range xs {
		productAll = mul(productAll, xi)
	}
	// Precompute Lagrange coefficients l_i = (productAll / xi) * inv(∏_{j≠i}(xi - xj))
	lags := make([]byte, n)
	for i := 0; i < n; i++ {
		denom := byte(1)
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			denom = mul(denom, sub(xs[i], xs[j]))
		}
		invXS, err := inv(xs[i])
		if err != nil {
			return nil, err
		}
		invDenom, err := inv(denom)
		if err != nil {
			return nil, err
		}
		lags[i] = mul(mul(productAll, invXS), invDenom)
	}
	secret := make([]byte, length-2)
	// For each byte position in secret part, apply precomputed Lagrange coefficients
	for j := 2; j < length; j++ {
		var value byte = 0
		for i := 0; i < n; i++ {
			yi := shares[i][j]
			value = add(value, mul(yi, lags[i]))
		}
		secret[j-2] = value
	}
	return secret, nil
}

// StoreShares stores all provided shares into the given storage.
func StoreShares(shares [][]byte, storage storage.IStorage) error {
	for _, share := range shares {
		index := share[0]
		if err := storage.SetShare(index, share); err != nil {
			return err
		}
	}
	return nil
}

// RetrieveShares gets shares from storage based on a list of indices.
func RetrieveShares(indices []byte, storage storage.IStorage) ([][]byte, error) {
	var shares [][]byte
	for _, idx := range indices {
		share, err := storage.GetShare(idx)
		if err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}
	return shares, nil
}

// MultiPartyAuthorize retrieves shares from storage and combines them if the threshold is met.
// This enforces that a quorum of custodians must collaborate to reconstruct the secret.
func MultiPartyAuthorize(storage storage.IStorage, indices []byte, threshold int) ([]byte, error) {
	shares, err := RetrieveShares(indices, storage)
	if err != nil {
		return nil, err
	}
	if len(shares) < threshold {
		return nil, errors.New("shamir: insufficient shares for multi-party authorization")
	}
	// Combine using only the first 'threshold' shares if extra are provided.
	return Combine(shares, threshold)
}

// BreakGlassRecovery demonstrates recovery using pre-designated "break-glass" shares.
// In practice, these shares should be stored in entirely separate secure locations.
func BreakGlassRecovery(storage storage.IStorage, recoveryIndices []byte, threshold int) ([]byte, error) {
	shares, err := RetrieveShares(recoveryIndices, storage)
	if err != nil {
		return nil, err
	}
	if len(shares) < threshold {
		return nil, errors.New("shamir: insufficient recovery shares for break-glass procedure")
	}
	return Combine(shares, threshold)
}
