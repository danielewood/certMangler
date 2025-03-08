#!/bin/bash

# go to git root
cd "$(git rev-parse --show-toplevel)" || exit 1

# Set the output directory from the first argument or default to 'temp'
OUTDIR="${1:-temp}"

# Create the necessary directories for PEM and DER keys
mkdir -p "$OUTDIR/keys/pem" "$OUTDIR/keys/der"

# Function to generate RSA keys
generate_rsa_keys() {
    for bits in 512 1024 2048 4096 8192; do
        # PEM Key
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$bits -out "$OUTDIR/keys/pem/rsa_${bits}.pem"
        # DER Key (separate)
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$bits -out "$OUTDIR/keys/der/rsa_${bits}_raw.pem"
        openssl rsa -in "$OUTDIR/keys/der/rsa_${bits}_raw.pem" -outform DER -out "$OUTDIR/keys/der/rsa_${bits}.der"
        rm "$OUTDIR/keys/der/rsa_${bits}_raw.pem"
    done
}

# Function to generate ECDSA keys
generate_ecdsa_keys() {
    for curve in prime256v1 secp384r1 secp521r1; do
        # PEM Key
        openssl ecparam -name $curve -genkey -noout -out "$OUTDIR/keys/pem/ecdsa_${curve}.pem"
        # DER Key (separate)
        openssl ecparam -name $curve -genkey -noout -out "$OUTDIR/keys/der/ecdsa_${curve}_raw.pem"
        openssl ec -in "$OUTDIR/keys/der/ecdsa_${curve}_raw.pem" -outform DER -out "$OUTDIR/keys/der/ecdsa_${curve}.der"
        rm "$OUTDIR/keys/der/ecdsa_${curve}_raw.pem"
    done
}

# Function to generate Ed25519 and Ed448 keys
generate_ed_keys() {
    for curve in Ed25519 Ed448; do
        # PEM Key
        openssl genpkey -algorithm $curve -out "$OUTDIR/keys/pem/${curve,,}.pem"
        # DER Key (separate)
        openssl genpkey -algorithm $curve -out "$OUTDIR/keys/der/${curve,,}_raw.pem"
        openssl pkey -in "$OUTDIR/keys/der/${curve,,}_raw.pem" -outform DER -out "$OUTDIR/keys/der/${curve,,}.der"
        rm "$OUTDIR/keys/der/${curve,,}_raw.pem"
    done
}

# Function to generate DH keys
generate_dh_keys() {
    # PEM Key
    openssl genpkey -genparam -algorithm DH -pkeyopt dh_paramgen_prime_len:2048 -out "$OUTDIR/keys/pem/dh_param.pem"
    openssl genpkey -paramfile "$OUTDIR/keys/pem/dh_param.pem" -out "$OUTDIR/keys/pem/dh_key.pem"
    # DER Key (separate)
    openssl genpkey -genparam -algorithm DH -pkeyopt dh_paramgen_prime_len:2048 -out "$OUTDIR/keys/der/dh_param_raw.pem"
    openssl genpkey -paramfile "$OUTDIR/keys/der/dh_param_raw.pem" -out "$OUTDIR/keys/der/dh_key.der"
    rm "$OUTDIR/keys/der/dh_param_raw.pem"
}

# Function to generate DH parameters
generate_dh_params() {
    # PEM Parameter
    openssl dhparam -out "$OUTDIR/keys/pem/dh_2048.pem" 2048
    # DER Parameter (separate)
    openssl dhparam -out "$OUTDIR/keys/der/dh_2048_raw.pem" 2048
    openssl dhparam -in "$OUTDIR/keys/der/dh_2048_raw.pem" -outform DER -out "$OUTDIR/keys/der/dh_2048.der"
    rm "$OUTDIR/keys/der/dh_2048_raw.pem"
}

# Run all key generation functions
generate_rsa_keys
generate_ecdsa_keys
generate_ed_keys
generate_dh_keys
generate_dh_params

echo "Key generation completed. Separate PEM and DER keys are stored in $OUTDIR/keys/pem and $OUTDIR/keys/der directories."
