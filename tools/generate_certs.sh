#!/bin/bash

# go to git root
cd "$(git rev-parse --show-toplevel)" || exit 1

# Define output directories
BASE_DIR="input/certs"
mkdir -p "${BASE_DIR}"

# Generate RSA, ECDSA, and Ed25519 certificates
generate_rsa_cert() {
    local bits=$1
    local output_dir="${BASE_DIR}/rsa_${bits}"
    mkdir -p "${output_dir}"

    echo "Generating RSA ${bits}-bit CA certificate..."
    # Generate CA key and certificate
    openssl genpkey -algorithm RSA -out "${output_dir}/ca_key.pem" -pkeyopt rsa_keygen_bits:"${bits}"
    openssl req -new -x509 -key "${output_dir}/ca_key.pem" -out "${output_dir}/ca_cert.pem" -days 365 -subj "/CN=Test CA RSA ${bits}"

    # Generate leaf key
    openssl genpkey -algorithm RSA -out "${output_dir}/key.pem" -pkeyopt rsa_keygen_bits:"${bits}"
    
    # Generate CSR
    openssl req -new -key "${output_dir}/key.pem" -out "${output_dir}/cert.csr" -subj "/CN=example.com"
    
    # Sign the CSR with CA
    openssl x509 -req -in "${output_dir}/cert.csr" -CA "${output_dir}/ca_cert.pem" -CAkey "${output_dir}/ca_key.pem" \
        -CAcreateserial -out "${output_dir}/cert.pem" -days 365 -copy_extensions copyall \
        -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n")

    # Convert to DER format
    openssl rsa -in "${output_dir}/key.pem" -outform DER -out "${output_dir}/key.der"
    openssl x509 -in "${output_dir}/cert.pem" -outform DER -out "${output_dir}/cert.der"
}

generate_ecdsa_cert() {
    local curve=$1
    local output_dir="${BASE_DIR}/ecdsa_${curve}"
    mkdir -p "${output_dir}"

    echo "Generating ECDSA certificate with curve ${curve}..."
    # Generate CA key and certificate
    openssl ecparam -name "${curve}" -genkey -noout -out "${output_dir}/ca_key.pem"
    openssl req -new -x509 -key "${output_dir}/ca_key.pem" -out "${output_dir}/ca_cert.pem" -days 365 -subj "/CN=Test CA ECDSA ${curve}"

    # Generate leaf key
    openssl ecparam -name "${curve}" -genkey -noout -out "${output_dir}/key.pem"

    # Generate CSR
    openssl req -new -key "${output_dir}/key.pem" -out "${output_dir}/cert.csr" -subj "/CN=example.com"

    # Sign the CSR with CA
    openssl x509 -req -in "${output_dir}/cert.csr" -CA "${output_dir}/ca_cert.pem" -CAkey "${output_dir}/ca_key.pem" \
        -CAcreateserial -out "${output_dir}/cert.pem" -days 365 -copy_extensions copyall \
        -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n")

    # Convert to DER format
    openssl ec -in "${output_dir}/key.pem" -outform DER -out "${output_dir}/key.der"
    openssl x509 -in "${output_dir}/cert.pem" -outform DER -out "${output_dir}/cert.der"
}

generate_ed25519_cert() {
    local output_dir="${BASE_DIR}/ed25519"
    mkdir -p "${output_dir}"

    echo "Generating Ed25519 certificate..."
    # Generate CA key and certificate
    openssl genpkey -algorithm ED25519 -out "${output_dir}/ca_key.pem"
    openssl req -new -x509 -key "${output_dir}/ca_key.pem" -out "${output_dir}/ca_cert.pem" -days 365 -subj "/CN=Test CA Ed25519"

    # Generate leaf key
    openssl genpkey -algorithm ED25519 -out "${output_dir}/key.pem"

    # Generate CSR
    openssl req -new -key "${output_dir}/key.pem" -out "${output_dir}/cert.csr" -subj "/CN=example.com"

    # Sign the CSR with CA
    openssl x509 -req -in "${output_dir}/cert.csr" -CA "${output_dir}/ca_cert.pem" -CAkey "${output_dir}/ca_key.pem" \
        -CAcreateserial -out "${output_dir}/cert.pem" -days 365 -copy_extensions copyall \
        -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n")

    # Convert to DER format
    openssl pkey -in "${output_dir}/key.pem" -outform DER -out "${output_dir}/key.der"
    openssl x509 -in "${output_dir}/cert.pem" -outform DER -out "${output_dir}/cert.der"
}

# Generate keys and certificates
# RSA keys: 1024, 2048, 4096, 8192 bits
for bits in 1024 2048 4096 8192; do
    generate_rsa_cert "${bits}"
done

# ECDSA curves: prime256v1, secp384r1, secp521r1
for curve in prime256v1 secp384r1 secp521r1; do
    generate_ecdsa_cert "${curve}"
done

# Ed25519
generate_ed25519_cert

echo "All certificates and keys have been generated in ${BASE_DIR}."