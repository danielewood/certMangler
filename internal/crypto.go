package internal

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/jmoiron/sqlx/types"
	"golang.org/x/crypto/pkcs12"
)

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// getPublicKey extracts the public key from a private key
func getPublicKey(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", priv)
	}
}

// getKeyType returns a string description of the key type
func getKeyType(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", pub.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("unknown key type: %T", pub)
	}
}

// getCertificateType determines if a certificate is root, intermediate, or leaf
func getCertificateType(cert *x509.Certificate) string {
	// Check if it's a CA
	if cert.IsCA {
		// For root certificates, the issuer and subject will be identical
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			return "root"
		}
		return "intermediate"
	}
	return "leaf"
}

func computeSKIDRawBits(pub crypto.PublicKey, sumType ...string) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX: %v", err)
	}

	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("unmarshal SPKI: %v", err)
	}

	hashType := "sha1"
	if len(sumType) > 0 && sumType[0] != "" {
		hashType = sumType[0]
	}

	switch hashType {
	case "sha1":
		sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
		return sum[:], nil
	case "sha256":
		sum := sha256.Sum256(spki.SubjectPublicKey.Bytes)
		// Yes, first 40 characters, I think its dumb too
		return sum[:20], nil
	default:
		return nil, fmt.Errorf("unsupported hash type: %s", hashType)
	}
}

func isPEM(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN"))
}

func parsePrivateKey(data []byte, passwords []string) (crypto.PrivateKey, error) {
	if key, err := helpers.ParsePrivateKeyPEM(data); err == nil && key != nil {
		return key, nil
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if !x509.IsEncryptedPEMBlock(block) {
		return nil, fmt.Errorf("PEM block is not encrypted")
	}

	for _, password := range passwords {
		decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			continue
		}

		pemBlock := &pem.Block{
			Type:  block.Type,
			Bytes: decrypted,
		}
		key, err := helpers.ParsePrivateKeyPEM(pem.EncodeToMemory(pemBlock))
		if err == nil && key != nil {
			return key, nil
		}
	}

	return nil, fmt.Errorf("failed to decrypt private key with any password")
}

func processPEM(data []byte, path string, cfg *Config) {
	// Try parsing as certificates first
	if certs, err := helpers.ParseCertificatesPEM(data); err == nil && len(certs) > 0 {
		for _, cert := range certs {
			skid := "N/A"
			if len(cert.SubjectKeyId) > 0 {
				skid = hex.EncodeToString(cert.SubjectKeyId)
			} else {
				log.Errorf("No SKID found in certificate %s", cert.SerialNumber)
				continue
			}

			// For root certificates, if AKI is missing, use SKI
			aki := cert.AuthorityKeyId
			if len(aki) == 0 && cert.IsCA && bytes.Equal(cert.RawIssuer, cert.RawSubject) {
				aki = cert.SubjectKeyId
			}

			// Format SANs
			var sans []string
			sans = append(sans, cert.DNSNames...)
			for _, ip := range cert.IPAddresses {
				sans = append(sans, ip.String())
			}
			sansJSON, err := json.Marshal(sans)
			if err != nil {
				sansJSON = []byte("[]")
			}

			// Check if certificate is expired
			if time.Now().After(cert.NotAfter) {
				log.Debugf("Skipping expired certificate: CN=%s, Serial=%s, Expired=%v",
					cert.Subject.CommonName,
					cert.SerialNumber.String(),
					cert.NotAfter.Format(time.RFC3339))
				continue
			}

			// Determine bundle name from configuration
			bundleName := determineBundleName(cert.Subject.CommonName, cfg.BundleConfigs)
			log.Debugf("Determined bundle name %s for certificate CN=%s", bundleName, cert.Subject.CommonName)
			PEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})

			certRecord := CertificateRecord{
				Serial:               cert.SerialNumber.String(),
				AKI:                  hex.EncodeToString(aki),
				Type:                 getCertificateType(cert),
				KeyType:              getKeyType(cert),
				PEM:                  string(PEM),
				SubjectKeyIdentifier: hex.EncodeToString(cert.SubjectKeyId),
				NotBefore:            &cert.NotBefore,
				Expiry:               cert.NotAfter,
				CommonName:           sql.NullString{String: cert.Subject.CommonName, Valid: cert.Subject.CommonName != ""},
				SANsJSON:             types.JSONText(sansJSON),
				BundleName:           bundleName,
			}

			if err := cfg.DB.InsertCertificate(certRecord); err != nil {
				log.Warningf("Failed to insert certificate into the database: %v", err)
			} else {
				log.Debugf("Inserted certificate %s with SKID %s into database", cert.SerialNumber.String(), skid)
			}

			log.Infof("%s, certificate, sha:%s", path, skid)
		}
		return
	}

	// Try parsing as CSR
	if csr, err := helpers.ParseCSRPEM(data); err == nil && csr != nil {
		skid, skid256 := "N/A", "N/A"

		if pub := csr.PublicKey; pub != nil {
			if rawSKID, err := computeSKIDRawBits(pub); err == nil {
				skid = hex.EncodeToString(rawSKID)
				skid256 = hex.EncodeToString(rawSKID)
			} else {
				log.Debugf("computeSKIDRawBits error on %s (CSR): %v", path, err)
			}
		}
		log.Infof("%s, csr, sha1:%s, sha256:%s", path, skid, skid256)
		return
	}

	// Process all PEM blocks for private keys
	var rest []byte = data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			log.Debugf("No more valid PEM blocks found in %s", path)
			break
		}

		// Skip non-private key blocks
		if !strings.Contains(block.Type, "PRIVATE KEY") && block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
			continue
		}

		// Encode the block back to PEM for processing
		pemData := pem.EncodeToMemory(block)
		if key, err := parsePrivateKey(pemData, cfg.Passwords); err == nil && key != nil {
			skid := "N/A"
			skid256 := "N/A"
			if pub, err := getPublicKey(key); err == nil {
				log.Debugf("Got public key of type: %T", pub)
				if rawSKID, err := computeSKIDRawBits(pub); err == nil {
					skid = hex.EncodeToString(rawSKID)
					rawSKID256, _ := computeSKIDRawBits(pub, "sha256")
					skid256 = hex.EncodeToString(rawSKID256)
					keyRecord := KeyRecord{
						SubjectKeyIdentifier:       skid,
						SubjectKeyIdentifierSha256: skid256,
						KeyData:                    pemData,
					}
					if rsaKey, ok := key.(*rsa.PrivateKey); ok {
						keyRecord.KeyData = pem.EncodeToMemory(&pem.Block{
							Type:  "RSA PRIVATE KEY",
							Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
						})
						keyRecord.KeyType = "rsa"
						keyRecord.BitLength = rsaKey.N.BitLen()
						keyRecord.PublicExponent = rsaKey.E
						keyRecord.Modulus = rsaKey.N.String()
					} else if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
						keyBytes, _ := x509.MarshalECPrivateKey(ecdsaKey)
						keyRecord.KeyData = pem.EncodeToMemory(&pem.Block{
							Type:  "EC PRIVATE KEY",
							Bytes: keyBytes,
						})
						keyRecord.KeyType = "ecdsa"
						keyRecord.Curve = ecdsaKey.Curve.Params().Name
						keyRecord.BitLength = ecdsaKey.Curve.Params().BitSize
					} else if ed25519Key, ok := key.(ed25519.PrivateKey); ok {
						keyBytes, _ := x509.MarshalPKCS8PrivateKey(ed25519Key)
						keyRecord.KeyData = pem.EncodeToMemory(&pem.Block{
							Type:  "PRIVATE KEY",
							Bytes: keyBytes,
						})
						keyRecord.KeyType = "ed25519"
						keyRecord.BitLength = len(ed25519Key) * 8
					}

					if err := cfg.DB.InsertKey(keyRecord); err != nil {
						log.Warningf("Failed to insert key into database: %v", err)
					} else {
						log.Debugf("Inserted key with SKID %s into database", skid)
					}

				} else {
					log.Debugf("computeSKIDRawBits error on %s (private key): %v", path, err)
				}
			} else {
				log.Debugf("getPublicKey error on %s: %v", path, err)
			}
			log.Infof("%s, private key, sha1:%s, sha256:%s", path, skid, skid256)
		} else {
			log.Debugf("Failed to parse private key from PEM block in %s: %v", path, err)
		}
	}

	if len(rest) == len(data) {
		log.Debugf("Unrecognized PEM format in %s", path)
	}
}

func processDER(data []byte, path string, cfg *Config) {
	// Try parsing as a certificate first
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		log.Debugf("Successfully parsed single DER certificate")
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		processPEM(certPEM, path, cfg)
		return
	}

	// Try parsing as a certificate sequence
	certs, err := x509.ParseCertificates(data)
	if err == nil && len(certs) > 0 {
		log.Debugf("Successfully parsed DER certificate sequence with %d certificates", len(certs))
		for _, cert := range certs {
			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
			processPEM(certPEM, path, cfg)
		}
		return
	}

	// Try PKCS8
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil && key != nil {
		log.Debugf("Successfully parsed as PKCS8 private key of type %T", key)
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err == nil {
			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyDER,
			})
			processPEM(keyPEM, path, cfg)
			return
		}
	}

	// Try SEC1 EC
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		log.Debugf("Successfully parsed as SEC1 EC private key")
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err == nil {
			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyDER,
			})
			processPEM(keyPEM, path, cfg)
			return
		}
	}

	// Try parsing directly as ED25519 private key
	if len(data) == ed25519.PrivateKeySize {
		key := ed25519.PrivateKey(data)
		log.Debugf("Successfully parsed as ED25519 private key")
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err == nil {
			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyDER,
			})
			processPEM(keyPEM, path, cfg)
			return
		}
	}

	// Try PKCS#12 as last resort
	log.Debugf("Attempting PKCS#12 parsing")
	for _, password := range cfg.Passwords {
		pems, err := pkcs12.ToPEM(data, password)
		if err != nil {
			log.Debugf("Failed to extract safe bags with password '%s': %v", password, err)
			continue
		}

		for i, pemBlock := range pems {
			log.Debugf("Processing extracted PEM block %d from %s", i+1, path)
			pemData := pem.EncodeToMemory(pemBlock)
			processPEM(pemData, fmt.Sprintf("%s[%d]", path, i+1), cfg)
		}
		return
	}

	log.Debugf("Failed to parse DER data in any known format")
}

func ProcessFile(path string, cfg *Config) error {
	var data []byte
	var err error

	if cfg.IsStdinSet {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}

	if err != nil {
		return fmt.Errorf("could not read %s: %v", path, err)
	}

	log.Debugf("=== Processing %s ===", path)

	// Check if the data is PEM format
	if isPEM(data) {
		log.Debug("Processing as PEM format")
		processPEM(data, path, cfg)
		return nil
	}

	// If not PEM, try as DER
	if len(data) > 0 {
		log.Debug("Processing as DER format")
		processDER(data, path, cfg)
	}

	return nil
}
