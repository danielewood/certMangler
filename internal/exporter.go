package internal

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"software.sslmate.com/src/go-pkcs12"

	bundler "github.com/cloudflare/cfssl/bundler"
	"github.com/cloudflare/cfssl/helpers"
	"gopkg.in/yaml.v3"
)

// writeBundleFiles creates a folder for the bundle and writes multiple output files.
// The output folder structure will be:
//
//	outDir/bundleFolder/
//	  commonName.fullchain.pem
//	  commonName.p12
//	  commonName.csr.json
//	  commonName.key
//	  commonName.json
//	  commonName.yaml
//	  commonName.chain.pem
//	  commonName.csr
//	  commonName.pem
func writeBundleFiles(outDir, bundleFolder string, cert *CertificateRecord, key *KeyRecord, bundle *bundler.Bundle) error {
	// Use the certificate common name as the file prefix.
	prefix := cert.CommonName.String
	if prefix == "" {
		prefix = "unknown"
	}
	// Replace any asterisks (*) with underscores (_) for file names.
	prefix = strings.ReplaceAll(prefix, "*", "_")

	// Create the bundle folder (e.g., outDir/bundleFolder)
	folderPath := filepath.Join(outDir, bundleFolder)
	if err := os.MkdirAll(folderPath, 0755); err != nil {
		return err
	}

	// 1. Write the leaf certificate as <prefix>.pem.
	// Re-encode only the leaf certificate so that only one cert is output.
	leafPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: bundle.Cert.Raw, // use the raw DER bytes from the leaf certificate
	})
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".pem"), leafPEM, 0644); err != nil {
		return err
	}

	// 2. Build chain.pem as leaf + intermediates (excluding the root).
	var chainPEM []byte
	// Use the previously encoded leafPEM
	chainPEM = append(chainPEM, leafPEM...)
	// Append each certificate from the bundle starting from index 1 (skip the leaf)
	// but skip any certificate that is the root (if defined)
	for i, c := range bundle.Chain {
		if i == 0 {
			continue // skip leaf (already added)
		}
		if bundle.Root != nil && bytes.Equal(c.Raw, bundle.Root.Raw) {
			continue // skip the root certificate in chain.pem
		}
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".chain.pem"), chainPEM, 0644); err != nil {
		return err
	}

	// 3. Build fullchain.pem as leaf + intermediates + root (if available).
	var fullchainPEM []byte
	// Start with the chain (leaf + intermediates, as built above)
	fullchainPEM = append(fullchainPEM, chainPEM...)
	// Append the root certificate if it exists
	if bundle.Root != nil {
		fullchainPEM = append(fullchainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bundle.Root.Raw})...)
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".fullchain.pem"), fullchainPEM, 0644); err != nil {
		return err
	}

	// Write the key file.
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".key"), key.KeyData, 0600); err != nil {
		return err
	}

	// Generate and write the PKCS#12 (.p12) file.
	privKey, err := helpers.ParsePrivateKeyPEM(key.KeyData)
	if err != nil {
		return fmt.Errorf("failed to parse private key for P12: %v", err)
	}

	// Convert bundle certificates to slice
	var certs []*x509.Certificate
	certs = append(certs, bundle.Cert)
	certs = append(certs, bundle.Chain...)

	// Create PKCS#12 data with password "changeit"
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("failed to convert private key to signer")
	}
	p12Data, err := pkcs12.LegacyRC2.Encode(signer, bundle.Cert, certs[1:], "changeit")
	if err != nil {
		return fmt.Errorf("failed to create P12: %v", err)
	}

	if err := os.WriteFile(filepath.Join(folderPath, prefix+".p12"), p12Data, 0600); err != nil {
		return fmt.Errorf("failed to write P12 file: %v", err)
	}

	// Generate Kubernetes TLS secret YAML
	k8sSecret := K8sSecret{
		APIVersion: "v1",
		Kind:       "Secret",
		Type:       "kubernetes.io/tls",
		Metadata: K8sMetadata{
			Name: strings.TrimPrefix(bundleFolder, "_."),
		},
		Data: map[string]string{
			"tls.crt": base64.StdEncoding.EncodeToString([]byte(cert.PEM)),
			"tls.key": base64.StdEncoding.EncodeToString(key.KeyData),
		},
	}

	// Marshal to YAML
	k8sYAML, err := yaml.Marshal(k8sSecret)
	if err != nil {
		return fmt.Errorf("failed to marshal kubernetes secret yaml: %v", err)
	}

	// Write the k8s secret YAML
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".k8s.yaml"), k8sYAML, 0644); err != nil {
		return fmt.Errorf("failed to write kubernetes secret yaml: %v", err)
	}

	// 6. Generate and write the JSON file.
	jsonData, err := generateJSON(cert, key, bundle)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".json"), jsonData, 0644); err != nil {
		return err
	}

	// 7. Generate and write the YAML file.
	yamlData, err := generateYAML(cert, key, bundle)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".yaml"), yamlData, 0644); err != nil {
		return err
	}

	// 8. Generate and write a CSR (both PEM and JSON).
	// (Here we use a stub implementation; you should implement actual CSR generation as needed.)
	csrPEM, csrJSON, err := generateCSR(cert, key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".csr"), csrPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(folderPath, prefix+".csr.json"), csrJSON, 0644); err != nil {
		return err
	}

	return nil
}

// generateJSON creates a JSON representation of the certificate bundle.
func generateJSON(cert *CertificateRecord, key *KeyRecord, bundle *bundler.Bundle) ([]byte, error) {
	// Re-encode the leaf certificate (only the leaf, not the full chain)
	leafPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: bundle.Cert.Raw,
	})

	// Build the "pem" field as the concatenation of the leaf PEM plus any intermediate certificates.
	// (Skip the first element since that’s the leaf and skip any certificate equal to the root.)
	var chainPEM []byte
	chainPEM = append(chainPEM, leafPEM...)
	for i, c := range bundle.Chain {
		if i == 0 {
			continue // already added leaf
		}
		if bundle.Root != nil && bytes.Equal(c.Raw, bundle.Root.Raw) {
			continue // skip the root certificate in the "pem" field
		}
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})...)
	}

	// Prepare other fields
	authorityKeyID := ""
	if len(bundle.Cert.AuthorityKeyId) > 0 {
		authorityKeyID = fmt.Sprintf("%X", bundle.Cert.AuthorityKeyId)
	}

	subjectKeyID := ""
	if len(bundle.Cert.SubjectKeyId) > 0 {
		subjectKeyID = fmt.Sprintf("%X", bundle.Cert.SubjectKeyId)
	}

	notBefore := bundle.Cert.NotBefore.Format(time.RFC3339)
	notAfter := bundle.Cert.NotAfter.Format(time.RFC3339)

	serialNumber := bundle.Cert.SerialNumber.String()

	sigalg := helpers.SignatureString(bundle.Cert.SignatureAlgorithm)

	// Build the subject object – here we simply use the common name for both the "common_name" field
	subject := map[string]interface{}{
		"common_name": bundle.Cert.Subject.CommonName,
		"names":       []string{bundle.Cert.Subject.CommonName},
	}

	// Build subject alternative names (sans) from the certificate (if any)
	var sans []string
	sans = append(sans, bundle.Cert.DNSNames...)
	for _, ip := range bundle.Cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	out := map[string]interface{}{
		"authority_key_id": authorityKeyID,
		"issuer":           bundle.Cert.Issuer.String(),
		"not_after":        notAfter,
		"not_before":       notBefore,
		"pem":              string(chainPEM),
		"sans":             sans,
		"serial_number":    serialNumber,
		"sigalg":           sigalg,
		"subject":          subject,
		"subject_key_id":   subjectKeyID,
	}
	return json.MarshalIndent(out, "", "  ")
}

func buildFullchainPEM(cert *CertificateRecord, chain []*x509.Certificate) []byte {
	fullchain := []byte(cert.PEM)
	for _, c := range chain {
		fullchain = append(fullchain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return fullchain
}

// generateYAML creates a YAML representation of the certificate bundle.
func generateYAML(cert *CertificateRecord, key *KeyRecord, bundle *bundler.Bundle) ([]byte, error) {
	// Re-encode the leaf certificate using the bundle (leaf only)
	leafPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: bundle.Cert.Raw,
	})

	// Build the "bundle" field as the chain: start with the leaf, then append intermediates (skip root)
	var bundlePEM []byte
	bundlePEM = append(bundlePEM, leafPEM...)
	for i, c := range bundle.Chain {
		if i == 0 {
			continue // leaf already added
		}
		if bundle.Root != nil && bytes.Equal(c.Raw, bundle.Root.Raw) {
			continue // skip root in bundle field
		}
		bundlePEM = append(bundlePEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})...)
	}

	// Encode the root certificate (if available) for the "root" field.
	var rootPEM []byte
	if bundle.Root != nil {
		rootPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: bundle.Root.Raw,
		})
	}

	keyString := string(key.KeyData)
	keyString = strings.ReplaceAll(keyString, "\r\n", "\n")

	out := map[string]interface{}{
		"bundle":       string(bundlePEM),
		"crl_support":  false, // or set based on your data
		"crt":          string(leafPEM),
		"expires":      bundle.Expires.Format(time.RFC3339),
		"hostnames":    bundle.Hostnames,
		"issuer":       bundle.Issuer.String(),
		"key":          keyString,
		"key_size":     key.BitLength,
		"key_type":     key.KeyType,
		"leaf_expires": bundle.LeafExpires.Format(time.RFC3339),
		"ocsp":         bundle.Cert.OCSPServer,
		"ocsp_support": bundle.Cert.OCSPServer != nil,
		"root":         string(rootPEM),
		"signature":    helpers.SignatureString(bundle.Cert.SignatureAlgorithm),
		"status":       bundle.Status,
		"subject":      bundle.Subject.String(),
	}
	return yaml.Marshal(out)

}

// generateCSR creates a new CSR using the existing certificate's details and private key
func generateCSR(cert *CertificateRecord, key *KeyRecord) (csrPEM []byte, csrJSON []byte, err error) {
	// Parse the existing certificate
	block, _ := pem.Decode([]byte(cert.PEM))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}
	existingCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Parse the private key
	privKey, err := helpers.ParsePrivateKeyPEM(key.KeyData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Create CSR template using certificate details
	template := &x509.CertificateRequest{
		Subject:            existingCert.Subject,
		DNSNames:           existingCert.DNSNames,
		IPAddresses:        existingCert.IPAddresses,
		EmailAddresses:     existingCert.EmailAddresses,
		URIs:               existingCert.URIs,
		SignatureAlgorithm: existingCert.SignatureAlgorithm,
		ExtraExtensions:    []pkix.Extension{}, // Copy any needed extensions
	}

	// Create the CSR
	csrDER, err := x509.CreateCertificateRequest(nil, template, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %v", err)
	}

	// Encode CSR to PEM
	csrPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Parse the CSR to extract details for JSON
	parsedCSR, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated CSR: %v", err)
	}

	// Create detailed JSON representation
	csrDetails := map[string]interface{}{
		"subject": map[string]interface{}{
			"common_name":         parsedCSR.Subject.CommonName,
			"country":             parsedCSR.Subject.Country,
			"province":            parsedCSR.Subject.Province,
			"locality":            parsedCSR.Subject.Locality,
			"organization":        parsedCSR.Subject.Organization,
			"organizational_unit": parsedCSR.Subject.OrganizationalUnit,
		},
		"dns_names":           parsedCSR.DNSNames,
		"ip_addresses":        formatIPAddresses(parsedCSR.IPAddresses),
		"email_addresses":     parsedCSR.EmailAddresses,
		"key_algorithm":       formatKeyAlgorithm(parsedCSR.PublicKey),
		"signature_algorithm": helpers.SignatureString(parsedCSR.SignatureAlgorithm),
		"pem":                 string(csrPEM),
	}

	// Marshal the CSR details to JSON
	csrJSON, err = json.MarshalIndent(csrDetails, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal CSR JSON: %v", err)
	}

	return csrPEM, csrJSON, nil
}

// formatIPAddresses converts IP addresses to strings
func formatIPAddresses(ips []net.IP) []string {
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}

// formatKeyAlgorithm returns a string description of the public key algorithm
func formatKeyAlgorithm(pub interface{}) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("Unknown (%T)", pub)
	}
}

// ExportBundles iterates over all key records in the database, finds the matching
// certificate record, builds a certificate bundle using CFSSL’s bundler, and writes out
// the bundle files into a folder. If multiple certificates share the same BundleName,
// only the newest certificate (by NotBefore) gets the bare bundle name; all others have
// their serial appended.
func ExportBundles(cfgs []BundleConfig, outDir string, db *DB) error {
	// Create a new bundler instance (passing empty strings for CA/intermediate bundle file paths).
	bundlerInstance, err := bundler.NewBundler("", "")
	if err != nil {
		return fmt.Errorf("failed to create bundler: %v", err)
	}

	// Retrieve all key records from the database.
	keys, err := db.GetAllKeys()
	if err != nil {
		return fmt.Errorf("failed to get keys: %v", err)
	}

	// Process each key record.
	for _, key := range keys {
		// Retrieve the matching certificate record by subject key identifier (try both SHA1 and SHA256)
		cert, err := db.GetCertBySKI(key.SubjectKeyIdentifier)
		if err != nil || cert == nil {
			// If no match found with SHA1 SKI, try SHA256 SKI if it exists
			if len(key.SubjectKeyIdentifierSha256) > 0 {
				cert, err = db.GetCertBySKI(key.SubjectKeyIdentifierSha256)
				if err != nil || cert == nil {
					continue
				}
			} else {
				continue
			}
		}

		// Build a bundle from the certificate and its corresponding key.
		bundle, err := bundlerInstance.BundleFromPEMorDER([]byte(cert.PEM), key.KeyData, "optimal", "")
		if err != nil {
			log.Warningf("Failed to bundle cert %s: %v", cert.Serial, err)
			continue
		}

		// Determine the base bundle name from configuration
		bundleName := determineBundleName(cert.CommonName.String, cfgs)
		// Start with the base bundle name
		bundleFolder := cert.Serial

		// If we have a configured bundle name, process all certificates for this BundleName.
		if bundleName != "" {
			var certs []CertificateRecord
			err = db.Select(&certs,
				"SELECT * FROM certificates WHERE bundle_name = ? ORDER BY expiry DESC",
				bundleName)
			if err != nil {
				log.Errorf("Failed to retrieve certificates for bundle name %s: %v", bundleName, err)
				continue
			}

			// Iterate through all certificates for this BundleName
			for i, bundleCert := range certs {
				// Determine the folder name
				if i == 0 {
					// The newest certificate gets the base bundle name
					bundleFolder = bundleName
					log.Debugf("Using base name %s for newest certificate (CN=%s)", bundleName, cert.CommonName.String)
				} else {
					// Format expiration date as YYYY-MM-DD
					expirationDate := bundleCert.Expiry.Format("2006-01-02")
					// Construct the suffix with expiration date and serial number
					bundleFolder = fmt.Sprintf("%s_%s_%s", bundleName, expirationDate, bundleCert.Serial)
					log.Debugf("Using %s for older certificate (newest is %s, CN=%s)", bundleFolder, certs[0].Serial, cert.CommonName.String)
				}

				// Create the bundle folder
				folderPath := filepath.Join(outDir, bundleFolder)
				if err := os.MkdirAll(folderPath, 0755); err != nil {
					log.Errorf("Failed to create output directory %s: %v", folderPath, err)
					continue
				}

				// Write all bundle files for this specific certificate
				if err := writeBundleFiles(outDir, bundleFolder, &bundleCert, &key, bundle); err != nil {
					log.Warningf("Failed to write bundle files for cert %s: %v", bundleCert.Serial, err)
					continue
				}
				log.Infof("Exported bundle for %s into folder %s/%s", bundleCert.CommonName.String, outDir, bundleFolder)
			}
			continue
		}

		// If we have a configured bundle name, check for duplicates
		if bundleName != "" {
			// First check if there are multiple certificates with this bundle name
			var count int
			err = db.Get(&count, "SELECT COUNT(*) FROM certificates WHERE bundle_name = ?", bundleName)
			if err == nil && count > 1 {
				log.Debugf("Found %d certificates for bundle name %s", count, bundleName)

				// Only if we have multiple certificates, determine the newest
				var certs []CertificateRecord
				err = db.Select(&certs,
					"SELECT * FROM certificates WHERE bundle_name = ? ORDER BY not_before DESC",
					bundleName)
				if err == nil && len(certs) > 0 {
					// If this isn't the newest certificate (first in the ordered list)
					if certs[0].Serial != cert.Serial {
						// Append the serial to make the folder name unique
						bundleFolder = bundleName + "_" + cert.Serial
						log.Debugf("Using %s for older certificate (newest is %s, CN=%s)",
							bundleFolder, certs[0].Serial, cert.CommonName.String)
					} else {
						log.Debugf("Using base name %s for newest certificate (CN=%s)",
							bundleFolder, cert.CommonName.String)
					}
				}
			}
		}

		// Create the bundle folder using the potentially modified bundleFolder name
		// (will include serial number for older certificates)
		folderPath := filepath.Join(outDir, bundleFolder)
		if err := os.MkdirAll(folderPath, 0755); err != nil {
			log.Errorf("Failed to create output directory %s: %v", folderPath, err)
			continue
		}

		// Write all bundle files into the folder.
		if err := writeBundleFiles(outDir, bundleFolder, cert, &key, bundle); err != nil {
			log.Warningf("Failed to write bundle files for cert %s: %v", cert.Serial, err)
			continue
		}

		// Display the result using the certificate's CommonName.
		log.Infof("Exported bundle for %s into folder %s/%s", cert.CommonName.String, outDir, bundleFolder)
	}

	return nil
}

// determineBundleName determines the bundle name for a certificate based on the provided bundle configurations.
// When multiple certificates match the same configuration, only the newest certificate (as determined by NotBefore)
// will get the bare bundle name. All subsequent certificates will have their serial appended.
func determineBundleName(cn string, configs []BundleConfig) string {
	for _, cfg := range configs {
		for _, pattern := range cfg.CommonNames {
			// Only exact matches are allowed
			if pattern == cn {
				if cfg.BundleName != "" {
					return cfg.BundleName
				}
				// For a config without an explicit BundleName, use CN with any "*" replaced
				cn = strings.ReplaceAll(cn, "*", "_")
				return cn
			}
		}
	}
	// If no configuration matched, use CN with any "*" replaced
	cn = strings.ReplaceAll(cn, "*", "_")
	return cn
}
