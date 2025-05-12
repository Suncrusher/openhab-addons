#!/bin/bash

# === Constants ===
# CRC16 polynomial (CRC16-CCITT)
POLYNOM_CRC16_CCIT=0x8408

# === Configuration Parameters (from SmartMeterOSGPConfiguration) ===
SERIAL_PORT="/dev/ttyUSB0"      # Serial port to use (e.g., /dev/ttyUSB0)
USER_ID=1                       # User ID
USERNAME=""                     # Username for authentication
PASSWORD="e329b0428c16c74c0125" # Password for authentication
REFRESH_INTERVAL=2              # Data refresh interval in seconds
LOGOFF_INTERVAL=$((9 * 60))     # Logoff interval in seconds (9 minutes)
IDLE_START_TIME="02:10:00"      # Idle start time (HH:MM:SS)
IDLE_SECONDS=$((8 * 60))        # Idle duration in seconds (8 minutes)

# === Functions ===

# Parse time strings into seconds since midnight
time_to_seconds() {
    local time="$1"
    IFS=: read -r hours minutes seconds <<< "$time"
    echo $((10#$hours * 3600 + 10#$minutes * 60 + 10#$seconds))
}

# Check if the current time is in the idle period
is_idle_period() {
    local current_time=$(date "+%H:%M:%S")
    local current_seconds=$(time_to_seconds "$current_time")
    local idle_start_seconds=$(time_to_seconds "$IDLE_START_TIME")
    local idle_end_seconds=$((idle_start_seconds + IDLE_SECONDS))

    # Handle idle period crossing midnight
    if ((idle_start_seconds <= idle_end_seconds)); then
        ((current_seconds >= idle_start_seconds && current_seconds < idle_end_seconds))
    else
        ! ((current_seconds >= idle_end_seconds && current_seconds < idle_start_seconds))
    fi
}

# Generate CRC16 lookup table
generate_crc16_table() {
    local polynom=$1
    local table=()
    for ((x=0; x<256; x++)); do
        local w=$x
        for ((i=0; i<8; i++)); do
            if ((w & 1)); then
                w=$(( (w >> 1) ^ polynom ))
            else
                w=$((w >> 1))
            fi
        done
        table[$x]=$w
    done
    echo "${table[@]}"
}

# Calculate CRC16 for a byte array
calculate_crc16() {
    local bytes=("$@")
    local crc=0xFFFF
    local table=($(generate_crc16_table $POLYNOM_CRC16_CCIT))

    for byte in "${bytes[@]}"; do
        local index=$(( (crc ^ byte) & 0xFF ))
        crc=$(( (crc >> 8) ^ table[index] ))
    done

    # Complement the result
    echo $((crc ^ 0xFFFF))
}

# Configure the serial port
configure_serial_port() {
    if [ -z "$SERIAL_PORT" ]; then
        echo "Error: SERIAL_PORT is not configured."
        exit 1
    fi

    stty -F "$SERIAL_PORT" "$BAUD_RATE" cs"$DATA_BITS" -cstopb -parenb
    echo "Configured serial port $SERIAL_PORT."
}

# Send data to the USB device
send_data() {
    local data=("$@")
    echo -ne "${data[@]}" > "$SERIAL_PORT"
    echo "Sent data: ${data[@]}"
}

# Read data from the USB device
read_data() {
    local timeout="$1"
    local data
    exec 3<"$SERIAL_PORT"
    read -t "$timeout" -u 3 data
    exec 3<&-
    if [ -n "$data" ]; then
        echo "Received data: $data"
    else
        echo "No data received within $timeout seconds."
    fi
}

# Send a CRC16-validated message
send_crc16_message() {
    local message=("$@")
    local crc=$(calculate_crc16 "${message[@]}")

    # Append CRC16 to the message
    message+=($((crc & 0xFF)) $(((crc >> 8) & 0xFF)))

    echo "Sending message with CRC16: ${message[*]}"
    send_data "${message[@]}"

    # Wait for acknowledgment or response
    read_data 5
}

# Authenticate with the smart meter
authenticate() {
    echo "Authenticating with username: $USERNAME and user ID: $USER_ID"

    # Create logon request (example format)
    local logon_request=(0x01 "$USER_ID" "$USERNAME")
    send_crc16_message "${logon_request[@]}"

    # Send password
    send_password "$PASSWORD"

    echo "Authentication completed."
}

# Send a password securely
send_password() {
    local password="$1"
    local padded_password

    # Pad the password to 20 bytes with null characters
    padded_password=$(printf "%-20s" "$password" | tr ' ' '\0')

    echo "Sending password..."
    send_data "$padded_password"

    # Wait for acknowledgment or response
    read_data 5
}

# Poll the meter for status updates
poll_status() {
    echo "Polling device for status..."
    local poll_request=(0x02) # Example poll request
    send_crc16_message "${poll_request[@]}"
    read_data 5
}

# Start the main communication loop
main() {
    # Ensure the serial port exists
    if [ ! -e "$SERIAL_PORT" ]; then
        echo "Error: Serial port $SERIAL_PORT does not exist."
        exit 1
    fi

    # Configure the serial port
    configure_serial_port

    # Authenticate with the device
    authenticate

    # Poll periodically unless in idle period
    while true; do
        if is_idle_period; then
            echo "Device is in idle period. Skipping polling."
            sleep "$REFRESH_INTERVAL"
            continue
        fi

        poll_status
        sleep "$REFRESH_INTERVAL"
    done
}

# Execute the main function
main
