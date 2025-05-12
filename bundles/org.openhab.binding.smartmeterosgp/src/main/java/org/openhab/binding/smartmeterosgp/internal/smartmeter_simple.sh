#!/bin/bash

# === Constants ===
POLYNOM_CRC16_CCIT=0x8408
SERIAL_PORT="/dev/ttyUSB0"
REFRESH_INTERVAL=2
LOGOFF_INTERVAL=$((9 * 60))  # 9 minutes
IDLE_START_TIME="02:10:00"
IDLE_SECONDS=$((8 * 60))  # 8 minutes
DATA_FILE="data.txt"
USER_ID=1
USERNAME=""
PASSWORD="e329b0428c16c74c0125"

# Define headers based on SmartMeterOSGPBindingConstants.java
HEADERS=("Fwd_active_energy" "Rev_active_energy" "Fwd_active_power" "Rev_active_power" \
"Import_Reactive_VAr" "Export_Reactive_VAr" "L1_current" "L2_current" "L3_current" \
"L1_voltage" "L2_voltage" "L3_voltage")

# === Functions ===

# Initialize CSV file with headers
initialize_csv() {
    if [ ! -f "$DATA_FILE" ]; then
        echo "Initializing $DATA_FILE with headers..."
        echo "${HEADERS[*]}" | tr ' ' ',' > "$DATA_FILE"
    fi
}

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

    stty -F "$SERIAL_PORT" 9600 cs8 -cstopb -parenb
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
        echo "$data"
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

# Parse raw data into columns
parse_data() {
    local raw_data="$1"
    # Simulated parsing logic (update this according to your data format)
    local parsed_data=($(echo "$raw_data" | awk '{for (i=1; i<=NF; i++) print $i}'))

    # Ensure parsed data matches headers
    if [ "${#parsed_data[@]}" -ne "${#HEADERS[@]}" ]; then
        echo "Error: Parsed data does not match expected column count."
        return 1
    fi

    echo "${parsed_data[@]}"
}

# Append parsed data to CSV file
append_to_csv() {
    local parsed_data=("$@")
    echo "${parsed_data[*]}" | tr ' ' ',' >> "$DATA_FILE"
}

# Main function to read, parse, and save data
main_loop() {
    echo "Starting data collection..."
    while true; do
        # Skip polling during idle period
        if is_idle_period; then
            echo "Device is in idle period. Skipping polling."
            sleep "$REFRESH_INTERVAL"
            continue
        fi

        # Poll the device for data
        poll_status

        # Read and process data
        local raw_data
        raw_data=$(read_data "$REFRESH_INTERVAL")
        if [ -n "$raw_data" ]; then
            echo "Raw Data: $raw_data"

            local parsed_data
            parsed_data=$(parse_data "$raw_data")
            if [ $? -eq 0 ]; then
                echo "Parsed Data: $parsed_data"
                append_to_csv $parsed_data
            fi
        fi

        sleep "$REFRESH_INTERVAL"
    done
}

# === Script Execution ===

# Initialize the CSV file
initialize_csv

# Configure the serial port
configure_serial_port

# Authenticate with the device
authenticate

# Start the main loop
main_loop
