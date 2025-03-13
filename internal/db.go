package internal

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	_ "github.com/mattn/go-sqlite3"
)

// DB represents the database connection.
type DB struct {
	*sqlx.DB
}

// GetAllKeys returns all key records from the database.
func (db *DB) GetAllKeys() ([]KeyRecord, error) {
	var keys []KeyRecord
	err := db.Select(&keys, "SELECT * FROM keys")
	if err != nil {
		return nil, fmt.Errorf("failed to get all keys: %w", err)
	}
	return keys, nil
}

// GetCertBySKI returns the certificate record matching the given subject key identifier.
func (db *DB) GetCertBySKI(skid string) (*CertificateRecord, error) {
	var cert CertificateRecord
	err := db.Get(&cert, "SELECT * FROM certificates WHERE subject_key_identifier = ?", skid)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get certificate by SKI: %w", err)
	}
	return &cert, nil
}

// NewDB creates and initializes a new database connection.
func NewDB(dbPath string) (*DB, error) {
	// Determine connection string
	connectionString := ":memory:"
	if dbPath != "" {
		connectionString = dbPath
	}

	// Open database connection
	db, err := sqlx.Open("sqlite3", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	dbObj := &DB{DB: db}

	// Initialize database schema
	if err := dbObj.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	log.Debugf("Database initialized (path: %s)", connectionString)

	return dbObj, nil
}

func (db *DB) initSchema() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
			expiry                   timestamp,
			not_before              timestamp,
			common_name             text,
			sans                    text,
			subject_key_identifier  text NOT NULL,
			key_type                text NOT NULL,
			pem                     blob NOT NULL,
			serial_number            blob NOT NULL,
			authority_key_identifier blob NOT NULL,
			cert_type               text NOT NULL,
			metadata                text,
			bundle_name             text NOT NULL,
			PRIMARY KEY(serial_number, authority_key_identifier, subject_key_identifier)
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to create certificates table: %w", err)
	}

	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_certificates_skid ON certificates (subject_key_identifier);
	`)
	if err != nil {
		return fmt.Errorf("failed to create subject key identifier index on certificates table: %w", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			subject_key_identifier TEXT PRIMARY KEY,
			subject_key_identifier_sha256 TEXT,
			key_type TEXT,
			bit_length INTEGER,
			public_exponent INTEGER,
			modulus TEXT,
			curve TEXT,
			key_data BLOB NOT NULL
		);
	`)

	if err != nil {
		return fmt.Errorf("failed to create keys table: %w", err)
	}
	return nil
}

func (db *DB) InsertKey(key KeyRecord) error {
	_, err := db.NamedExec(`
		INSERT INTO keys (subject_key_identifier, subject_key_identifier_sha256, key_type, bit_length, public_exponent, modulus, curve, key_data)
		VALUES (:subject_key_identifier, :subject_key_identifier_sha256, :key_type, :bit_length, :public_exponent, :modulus, :curve, :key_data)
	`, key)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		log.Debugf("Skipping duplicate key: %v", err)
		return nil
	}
	return err
}

// InsertCertificate inserts a new certificate record into the database.
func (db *DB) InsertCertificate(cert CertificateRecord) error {
	_, err := db.NamedExec(`
		INSERT INTO certificates (serial_number, authority_key_identifier, cert_type, key_type, expiry, not_before, metadata, sans, common_name, bundle_name, subject_key_identifier, pem)
		VALUES (:serial_number, :authority_key_identifier, :cert_type, :key_type, :expiry, :not_before, :metadata, :sans, :common_name, :bundle_name, :subject_key_identifier, :pem)
	`, cert)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		log.Debugf("Skipping duplicate certificate: %v", err)
		return nil
	}
	return err
}

func (db *DB) GetKey(skid string, skid256 string) (*KeyRecord, error) {
	var key KeyRecord
	err := db.Get(&key, "SELECT * FROM keys WHERE subject_key_identifier = ? OR subject_key_identifier_sha256 = ?", skid, skid256)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not an error, just means the key doesn't exist
		}
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	return &key, nil
}

func (db *DB) GetCert(serial, aki string) (*CertificateRecord, error) {
	var cert CertificateRecord
	err := db.Get(&cert, "SELECT * FROM certificates WHERE serial_number = ? AND authority_key_identifier = ?", serial, aki)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not an error, just means the certificate doesn't exist
		}
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}
	return &cert, nil
}

// formatTimePtr formats a time pointer, returning "N/A" if nil
func formatSANs(sans types.JSONText) string {
	if len(sans) == 0 {
		return "none"
	}
	return string(sans)
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return "N/A"
	}
	return t.String()
}

func (db *DB) DumpDB() error {
	// Helper function to print formatted headers
	printHeader := func(title string) {
		divider := strings.Repeat("=", 10)
		log.Debugf(divider)
		log.Debugf(title)
		log.Debugf(divider)
	}

	// Print certificates
	printHeader("CERTIFICATES")

	rows, err := db.Queryx("SELECT * FROM certificates")
	if err != nil {
		return fmt.Errorf("failed to query certificates: %w", err)
	}
	defer rows.Close()

	certCount := 0
	for rows.Next() {
		var cert CertificateRecord
		if err := rows.StructScan(&cert); err != nil {
			return fmt.Errorf("failed to scan certificate: %w", err)
		}
		log.Debugf("Certificate Details:"+
			"\n\tSKI: %s"+
			"\n\tCN: %s"+
			"\n\tBundleName: %s"+
			"\n\tSerial: %s"+
			"\n\tAKI: %s"+
			"\n\tType: %s"+
			"\n\tKey Type: %s"+
			"\n\tSANs: %s"+
			"\n\tNot Before: %v"+
			"\n\tExpiry: %v",
			cert.SubjectKeyIdentifier,
			cert.CommonName.String,
			cert.BundleName,
			cert.Serial,
			cert.AKI,
			cert.Type,
			cert.KeyType,
			formatSANs(cert.SANsJSON),
			formatTimePtr(cert.NotBefore),
			cert.Expiry)
		certCount++
	}
	log.Debugf("Total Certificates: %d", certCount)

	// Print keys
	printHeader("KEYS")

	rows, err = db.Queryx("SELECT subject_key_identifier, subject_key_identifier_sha256, key_type FROM keys")
	if err != nil {
		return fmt.Errorf("failed to query keys: %w", err)
	}
	defer rows.Close()

	keyCount := 0
	for rows.Next() {
		var key KeyRecord
		if err := rows.StructScan(&key); err != nil {
			return fmt.Errorf("failed to scan key: %w", err)
		}
		log.Debugf("SKI: %s | SKI256: %s | Type: %s",
			key.SubjectKeyIdentifier,
			key.SubjectKeyIdentifierSha256,
			strings.ToUpper(key.KeyType))
		keyCount++
	}
	log.Debugf("Total Keys: %d", keyCount)

	return nil
}
