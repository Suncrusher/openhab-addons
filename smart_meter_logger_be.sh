#!/bin/bash
#
# Big-Endian Smart Meter Logger Script
# This script communicates with a smart meter using big-endian byte format.
# Version: 1.0
#

# Configuration
DEVICE="/dev/ttyUSB0"   # Serial device
PASSWORD="00000000"     # Default password
CSV_FILE="smart_meter_data.csv"
LOG_FILE="smart_meter_logger.log"
POLL_INTERVAL=60        # Interval in seconds

# Protocol constants
START_BYTE=0xEE
IDENTITY_BYTE=0x00
CRC16_CCIT_POLYNOM=0x1021  # Big-endian CRC-16 CCITT polynomial

# Helper function for logging
log_message() {
    local message="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# Generate CRC16 table
generate_crc16_table_big_endian() {
    local polynom=$CRC16_CCIT_POLYNOM
    local -a table

    for ((x = 0; x < 256; x++)); do
        local w=$((x << 8))  # Big-endian: shift left by 8 bits
        for ((i = 0; i < 8; i++)); do
            if ((w & 0x8000)); then
                w=$(((w << 1) ^ polynom))
            else
                w=$((w << 1))
            fi
        done
        table[$x]=$((w & 0xFFFF))  # Keep only 16 bits
    done

    echo "${table[@]}"
}

# Calculate CRC16 (big-endian)
calculate_crc16_big_endian() {
    local -a data=("$@")
    local -a crc_table=($(generate_crc16_table_big_endian))
    local crc=0xFFFF  # Initial CRC value

    for byte in "${data[@]}"; do
        if [[ "$byte" =~ ^0x ]]; then
            byte=$((byte))  # Convert hex string to integer
        fi
        local idx=$(((crc >> 8) ^ byte))
        crc=$(((crc << 8) ^ ${crc_table[$idx]}))
        crc=$((crc & 0xFFFF))  # Keep only 16 bits
    done

    echo $crc
}

# Send message
send_message_big_endian() {
    local -a message=("$@")
    local sequence=0  # Sequence byte
    local ctrl_byte=0

    # Calculate message length
    local length=${#message[@]}
    local len_high=$((length >> 8))
    local len_low=$((length & 0xFF))

    # Assemble protocol header
    local -a header=($START_BYTE $IDENTITY_BYTE $ctrl_byte $sequence $len_high $len_low)
    local -a full_message=("${header[@]}" "${message[@]}")

    # Calculate CRC16
    local crc=$(calculate_crc16_big_endian "${full_message[@]}")
    local crc_high=$((crc >> 8))
    local crc_low=$((crc & 0xFF))

    # Send message with CRC
    _send_bytes "${full_message[@]}" $crc_high $crc_low

    # Wait for acknowledgment
    wait_for_ack
}

# Wait for acknowledgment
wait_for_ack() {
    local tmp_file=$(mktemp)
    local received=false
    local max_attempts=5
    local response_timeout=2

    for ((attempt = 1; attempt <= max_attempts; attempt++)); do
        log_message "Waiting for response... (Attempt $attempt/$max_attempts)"
        sleep 0.5

        dd if="$DEVICE" of="$tmp_file" bs=1 count=10 iflag=nonblock 2>/dev/null
        if [[ -s "$tmp_file" ]]; then
            local first_byte=$(hexdump -v -e '1/1 "%02X"' -n 1 "$tmp_file")
            log_message "Response received: 0x$first_byte"

            if [[ "$first_byte" == "06" ]]; then
                log_message "ACK (0x06) received"
                received=true
                break
            elif [[ "$first_byte" == "15" ]]; then
                log_message "NACK (0x15) received"
                sleep 1
                continue
            else
                log_message "Unexpected response: 0x$first_byte"
            fi
        else
            log_message "No response received, retrying..."
        fi

        sleep $response_timeout
    done

    rm -f "$tmp_file"
    if ! $received; then
        log_message "No ACK received after $max_attempts attempts"
        return 1
    fi
    return 0
}

# Send bytes to the device
_send_bytes() {
    local tmp_file=$(mktemp)

    # Clear the buffer
    dd if="$DEVICE" iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true

    # Log the bytes being sent
    echo -n "Sending: " | tee -a "$LOG_FILE"
    for byte in "$@"; do
        if [[ "$byte" =~ ^0x ]]; then
            byte=$((byte))
        fi
        printf "%02X " $byte | tee -a "$LOG_FILE"
        printf "\\$(printf '%03o' $byte)" >> "$tmp_file"
    done
    echo | tee -a "$LOG_FILE"

    # Send the data
    dd if="$tmp_file" of="$DEVICE" bs=1 count=$# 2>/dev/null
    rm -f "$tmp_file"
    sleep 0.3
}

# Main function
main() {
    log_message "Big-Endian Smart Meter Logger started"
    log_message "Device: $DEVICE, Interval: $POLL_INTERVAL seconds"

    while true; do
        log_message "Attempting to communicate with the meter..."
        send_message_big_endian 0x20  # Example: Send Ident-Request
        sleep $POLL_INTERVAL
    done
}

# Start the script
main
