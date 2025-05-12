#!/bin/bash

# === Configuration Parameters ===
SERIAL_PORT="/dev/ttyUSB0"        # Specify the serial port
BAUD_RATE="9600"                 # Set the baud rate
REFRESH_INTERVAL=5               # Set the polling interval in seconds
IDLE_START_TIME="20:00:00"       # Start of the idle period
IDLE_SECONDS=3600                # Duration of the idle period in seconds
DEVICE_PASSWORD="e329b0428c16c74c0125" # Password for authentication
DEVICE_USER_ID="1"            # User ID for authentication
DEVICE_USERNAME=""          # Username for authentication

# === Logging Functions ===

# Log a message with a timestamp
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] $message" >> smart_meter.log
}

log_debug() { log_message "DEBUG" "$1"; }
log_info() { log_message "INFO" "$1"; }
log_warn() { log_message "WARN" "$1"; }
log_error() { log_message "ERROR" "$1"; }

# === Serial Communication Functions ===

# Configure the serial port
configure_serial_port() {
    local port="$1"
    local baud_rate="$2"

    log_info "Configuring serial port $port with baud rate $baud_rate..."
    stty -F "$port" "$baud_rate" cs8 -cstopb -parenb
    if [ $? -ne 0 ]; then
        log_error "Failed to configure serial port $port"
        return 1
    fi
    log_info "Serial port $port configured successfully."
    return 0
}

# Send data to the serial port
send_to_serial_port() {
    local port="$1"
    local data="$2"

    log_debug "Sending data to serial port: $data"
    echo -ne "$data" > "$port"
    if [ $? -ne 0 ]; then
        log_error "Failed to send data to serial port $port"
        return 1
    fi
    log_debug "Data sent successfully."
    return 0
}

# Read data from the serial port
read_from_serial_port() {
    local port="$1"
    local timeout="$2"

    log_debug "Reading data from serial port $port..."
    timeout "$timeout" cat "$port"
    if [ $? -ne 0 ]; then
        log_error "Failed to read data from serial port $port"
        return 1
    fi
    log_debug "Data read successfully."
    return 0
}

# === Authentication and Logon ===

# Send logon request
send_logon_request() {
    log_info "Sending logon request with User ID: $DEVICE_USER_ID and Username: $DEVICE_USERNAME..."
    local logon_command
    logon_command=$(printf "LOGON:%s:%s\n" "$DEVICE_USER_ID" "$DEVICE_USERNAME")
    send_to_serial_port "$SERIAL_PORT" "$logon_command" || {
        log_error "Failed to send logon request."
        return 1
    }
    log_info "Logon request sent successfully."
    return 0
}

# Send password for authentication
send_password() {
    log_info "Sending password for authentication..."
    local password_command
    password_command=$(printf "PASSWORD:%s\n" "$DEVICE_PASSWORD")
    send_to_serial_port "$SERIAL_PORT" "$password_command" || {
        log_error "Failed to send password."
        return 1
    }
    log_info "Password sent successfully."
    return 0
}

# Authenticate with the device
authenticate_device() {
    log_info "Authenticating with the device..."
    send_logon_request || return 1
    send_password || return 1
    log_info "Authentication successful."
    return 0
}

# === Data Parsing Function ===

# Parse raw data into a structured format
parse_data() {
    local raw_data="$1"

    log_debug "Parsing raw data: $raw_data"
    # Example: Simulate parsing into JSON
    local parsed_data
    parsed_data=$(echo "$raw_data" | awk '{printf "{\"channel\": \"%s\", \"value\": \"%s\"}", $1, $2}')
    log_debug "Parsed data: $parsed_data"
    echo "$parsed_data"
}

# === Polling and Idle Period Functions ===

# Convert time to seconds
time_to_seconds() {
    local time="$1"
    echo "$time" | awk -F: '{ print ($1 * 3600) + ($2 * 60) + $3 }'
}

# Check if the current time is within the idle period
is_idle_period() {
    local current_time
    current_time=$(date "+%H:%M:%S")
    local idle_start_seconds
    idle_start_seconds=$(time_to_seconds "$IDLE_START_TIME")
    local idle_end_seconds=$((idle_start_seconds + IDLE_SECONDS))
    local current_seconds
    current_seconds=$(time_to_seconds "$current_time")

    # Idle period crossing midnight
    if ((idle_start_seconds < 86400)); then
        [[ $current_seconds -ge $idle_start_seconds && $current_seconds -lt $idle_end_seconds ]]
    else
        [[ $current_seconds -ge $idle_start_seconds || $current_seconds -lt $idle_end_seconds ]]
    fi
}

# Poll the device for data
poll_status() {
    log_info "Polling the device for status..."

    if is_idle_period; then
        log_info "Within idle period. Skipping polling."
        return 0
    fi

    local raw_data
    raw_data=$(read_from_serial_port "$SERIAL_PORT" 5) || {
        log_error "Failed to read from serial port."
        return 1
    }

    local parsed_data
    parsed_data=$(parse_data "$raw_data") || {
        log_error "Failed to parse data."
        return 1
    }

    log_info "Device status updated: $parsed_data"
}

# === Concurrency Functions ===

# Start polling in the background
start_polling() {
    log_info "Starting polling in the background..."
    while true; do
        poll_status
        sleep "$REFRESH_INTERVAL"
    done &
    echo $! > polling_pid.txt
}

# Stop the polling process
stop_polling() {
    if [ -f polling_pid.txt ]; then
        kill "$(cat polling_pid.txt)"
        rm polling_pid.txt
        log_info "Polling process stopped."
    else
        log_warn "No polling process found."
    fi
}

# === Initialization and Main Logic ===

# Initialize the device
initialize_device() {
    log_info "Initializing the device..."
    configure_serial_port "$SERIAL_PORT" "$BAUD_RATE" || {
        log_error "Failed to configure serial port."
        return 1
    }
    authenticate_device || {
        log_error "Authentication failed."
        return 1
    }
    log_info "Device initialized successfully."
}

# Start the script
initialize_device
start_polling
