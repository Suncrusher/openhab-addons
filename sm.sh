#!/bin/bash

# Smart Meter OSGP Reader Script
# This script reads data from a smart meter using the C12.18 protocol via an optical interface
# and saves the data to a CSV file

# Configuration
DEVICE="/dev/ttyUSB0"
USER_ID=1
USERNAME="00000000"  # Standardwert, bei Bedarf anpassen
PASSWORD="00000000"  # Standardwert, bei Bedarf anpassen
CSV_FILE="smart_meter_data.csv"
POLL_INTERVAL=60     # Abfrageintervall in Sekunden

# Protokoll-Konstanten basierend auf dem OpenHAB-Binding
START_BYTE=0xEE
IDENTITY_BYTE=0x00
ACK=0x06
NACK=0x15
REQUEST_ID_IDENT=0x20
REQUEST_ID_NEGOTIATE2=0x61
REQUEST_ID_LOGON=0x50
REQUEST_ID_SECURITY=0x51
REQUEST_ID_READ_PARTIAL=0x3f
REQUEST_ID_LOGOFF=0x52
REQUEST_ID_TERMINATE=0x21

# CRC16-CCIT Tabelle vorgenerieren (basierend auf der Java-Implementierung)
declare -a CRC_TABLE
function generate_crc_table {
    POLYNOM=0x8408  # CRC16-CCIT
    for i in $(seq 0 255); do
        crc=$i
        for j in $(seq 0 7); do
            if (( (crc & 0x0001) != 0 )); then
                crc=$((crc >> 1))
                crc=$((crc ^ POLYNOM))
            else
                crc=$((crc >> 1))
            fi
        done
        CRC_TABLE[$i]=$crc
    done
}

# CRC16-Funktion
function calculate_crc16 {
    local data=("$@")
    local crc=0xFFFF
    
    for byte in "${data[@]}"; do
        index=$(( (crc & 0xFF) ^ (byte & 0xFF) ))
        crc=$(( (crc >> 8) ^ CRC_TABLE[index] ))
    done
    
    # XOR with 0xFFFF wie im Java-Code
    crc=$(( crc ^ 0xFFFF ))
    echo $crc
}

# Funktion zum Senden einer Nachricht und Empfangen der Antwort
function send_message {
    local message=("$@")
    local length=${#message[@]}
    local toggle=$TOGGLE_CONTROL
    
    # Nachricht aufbauen mit Header
    local packet=($START_BYTE $IDENTITY_BYTE $(( toggle )) 0x00 $(( length & 0xFF )) $(( (length >> 8) & 0xFF )))
    
    # Nachrichteninhalt hinzufügen
    for byte in "${message[@]}"; do
        packet+=($byte)
    done
    
    # CRC berechnen und hinzufügen
    local crc=$(calculate_crc16 "${packet[@]}")
    packet+=($((crc & 0xFF)) $(((crc >> 8) & 0xFF)))
    
    # Toggle Bit umschalten
    TOGGLE_CONTROL=$((1 - TOGGLE_CONTROL))
    
    # Paket in Hex formatieren für stty
    local hex_string=""
    for byte in "${packet[@]}"; do
        printf -v hex_byte "\\x%02X" $byte
        hex_string+=$hex_byte
    done
    
    # Debug-Ausgabe
    echo "Sending: ${hex_string}" >&2
    
    # Senden der Nachricht
    printf "${hex_string}" > $DEVICE
    
    # Auf ACK warten
    read -t 2 -N 1 response < $DEVICE
    response_hex=$(hexdump -v -e '1/1 "0x%02X "' <<< "$response")
    
    if [[ "$response_hex" == "0x06 " ]]; then
        echo "ACK empfangen" >&2
        return 0
    else
        echo "NACK oder unbekannte Antwort empfangen: $response_hex" >&2
        return 1
    fi
}

# Funktion zum Empfangen einer Nachricht
function receive_message {
    # Timeout für die Antwort
    local timeout=5
    local start_time=$(date +%s)
    local data=""
    local found_start=0

    # Warten auf Start-Byte
    while (( $(date +%s) - start_time < timeout )); do
        read -t 1 -N 1 byte < $DEVICE
        byte_hex=$(hexdump -v -e '1/1 "0x%02X"' <<< "$byte")
        
        if [[ "$byte_hex" == "0xEE" ]]; then
            data+=$byte
            found_start=1
            break
        fi
    done

    if [[ $found_start -eq 0 ]]; then
        echo "Timeout bei Empfang des Start-Bytes" >&2
        return 1
    fi
    
    # Lese Identity und Control
    read -t 2 -N 2 bytes < $DEVICE
    data+=$bytes
    
    # Lese Länge (2 Bytes)
    read -t 2 -N 2 length_bytes < $DEVICE
    data+=$length_bytes
    
    # Berechne Länge aus den empfangenen Bytes
    length_hex=$(hexdump -v -e '1/1 "%02X"' <<< "${length_bytes}")
    length=$((0x${length_hex:0:2} + 0x${length_hex:2:2} * 256))
    
    # Lese Daten gemäß der Länge
    read -t 5 -N $length payload < $DEVICE
    data+=$payload
    
    # Lese CRC (2 Bytes)
    read -t 2 -N 2 crc_bytes < $DEVICE
    data+=$crc_bytes
    
    # Sende ACK zurück
    printf "\x06" > $DEVICE
    
    # Gebe die empfangenen Daten zurück
    echo "$data"
}

# Funktion zum Parsen der Tabellenantwort
function parse_table_data {
    local data="$1"
    local table="$2"
    
    # Hier müssen die Bytes ab Position 6 (nach Header) geparst werden
    if [[ "$table" == "23" ]]; then
        # Tabelle 23: Vorwärts- und rückwärts aktive Energie
        fwd_energy=$(hexdump -s 8 -n 4 -v -e '1/4 "%d"' <<< "$data")
        rev_energy=$(hexdump -s 12 -n 4 -v -e '1/4 "%d"' <<< "$data")
        
        fwd_energy_kwh=$(echo "scale=3; $fwd_energy/1000.0" | bc)
        rev_energy_kwh=$(echo "scale=3; $rev_energy/1000.0" | bc)
        
        echo "Vorwärts aktive Energie: $fwd_energy_kwh kWh, Rückwärts aktive Energie: $rev_energy_kwh kWh" >&2
        echo "$fwd_energy_kwh,$rev_energy_kwh,,,,,,,,"
    elif [[ "$table" == "28" ]]; then
        # Tabelle 28: Aktuelle Leistungs- und Spannungswerte
        fwd_power=$(hexdump -s 8 -n 4 -v -e '1/4 "%d"' <<< "$data")
        rev_power=$(hexdump -s 12 -n 4 -v -e '1/4 "%d"' <<< "$data")
        import_reactive=$(hexdump -s 16 -n 4 -v -e '1/4 "%d"' <<< "$data")
        export_reactive=$(hexdump -s 20 -n 4 -v -e '1/4 "%d"' <<< "$data")
        l1_current=$(hexdump -s 24 -n 4 -v -e '1/4 "%d"' <<< "$data")
        l2_current=$(hexdump -s 28 -n 4 -v -e '1/4 "%d"' <<< "$data")
        l3_current=$(hexdump -s 32 -n 4 -v -e '1/4 "%d"' <<< "$data")
        l1_voltage=$(hexdump -s 36 -n 4 -v -e '1/4 "%d"' <<< "$data")
        l2_voltage=$(hexdump -s 40 -n 4 -v -e '1/4 "%d"' <<< "$data")
        l3_voltage=$(hexdump -s 44 -n 4 -v -e '1/4 "%d"' <<< "$data")
        
        l1_current_a=$(echo "scale=3; $l1_current/1000.0" | bc)
        l2_current_a=$(echo "scale=3; $l2_current/1000.0" | bc)
        l3_current_a=$(echo "scale=3; $l3_current/1000.0" | bc)
        l1_voltage_v=$(echo "scale=3; $l1_voltage/1000.0" | bc)
        l2_voltage_v=$(echo "scale=3; $l2_voltage/1000.0" | bc)
        l3_voltage_v=$(echo "scale=3; $l3_voltage/1000.0" | bc)
        
        echo "Vorwärts aktive Leistung: $fwd_power W, Rückwärts aktive Leistung: $rev_power W" >&2
        echo "Strom L1: $l1_current_a A, L2: $l2_current_a A, L3: $l3_current_a A" >&2
        echo "Spannung L1: $l1_voltage_v V, L2: $l2_voltage_v V, L3: $l3_voltage_v V" >&2
        
        echo ",,$fwd_power,$rev_power,$import_reactive,$export_reactive,$l1_current_a,$l2_current_a,$l3_current_a,$l1_voltage_v,$l2_voltage_v,$l3_voltage_v"
    fi
}

# Funktion zum Initialisieren der Verbindung
function initialize_connection {
    # Serielle Schnittstelle konfigurieren
    stty -F $DEVICE raw 9600 
    
    # Setze Toggle-Control zurück
    TOGGLE_CONTROL=0
    
    # Sende IDENT-Request
    echo "Sende Ident-Request..." >&2
    if ! send_message $REQUEST_ID_IDENT; then
        echo "FEHLER: Ident-Request fehlgeschlagen" >&2
        return 1
    fi
    
    # Sende NEGOTIATE-Request
    echo "Sende Negotiate-Request..." >&2
    if ! send_message $REQUEST_ID_NEGOTIATE2 0x40 0x00 0x02 0x01; then
        echo "FEHLER: Negotiate-Request fehlgeschlagen" >&2
        return 1
    fi
    
    # Sende LOGON-Request
    echo "Sende Logon-Request..." >&2
    local logon_msg=($REQUEST_ID_LOGON $(( USER_ID & 0xFF )) $(( (USER_ID >> 8) & 0xFF )))
    
    # Füge Benutzernamen hinzu (auffüllen mit Leerzeichen)
    for (( i=0; i<${#USERNAME} && i<10; i++ )); do
        logon_msg+=($(printf "%d" "'${USERNAME:$i:1}"))
    done
    
    # Fülle auf 10 Zeichen auf
    for (( i=${#USERNAME}; i<10; i++ )); do
        logon_msg+=(32)  # ASCII-Wert für Space
    done
    
    if ! send_message "${logon_msg[@]}"; then
        echo "FEHLER: Logon-Request fehlgeschlagen" >&2
        return 1
    fi
    
    # Sende SECURITY-Request (mit Passwort)
    echo "Sende Security-Request..." >&2
    local security_msg=($REQUEST_ID_SECURITY)
    
    # Füge Passwort hinzu
    for (( i=0; i<${#PASSWORD} && i<20; i++ )); do
        security_msg+=($(printf "%d" "'${PASSWORD:$i:1}"))
    done
    
    # Fülle auf 20 Zeichen auf
    for (( i=${#PASSWORD}; i<20; i++ )); do
        security_msg+=(0)  # Auffüllen mit 0
    done
    
    if ! send_message "${security_msg[@]}"; then
        echo "FEHLER: Security-Request fehlgeschlagen" >&2
        return 1
    fi
    
    echo "Verbindung hergestellt" >&2
    return 0
}

# Funktion zum Beenden der Verbindung
function terminate_connection {
    echo "Beende Verbindung..." >&2
    send_message $REQUEST_ID_LOGOFF
    send_message $REQUEST_ID_TERMINATE
}

# Funktion zum Lesen der Tabellendaten vom Zähler
function read_table {
    local table_id=$1
    local offset=$2
    local length=$3
    
    echo "Lese Tabelle $table_id..." >&2
    
    # Sende READ_PARTIAL-Request
    local request=($REQUEST_ID_READ_PARTIAL 
                  $(( table_id & 0xFF )) $(( (table_id >> 8) & 0xFF ))
                  $(( (offset >> 16) & 0xFF )) 
                  $(( offset & 0xFF )) $(( (offset >> 8) & 0xFF ))
                  $(( length & 0xFF )) $(( (length >> 8) & 0xFF )))
    
    if ! send_message "${request[@]}"; then
        echo "FEHLER: Lesen der Tabelle $table_id fehlgeschlagen" >&2
        return 1
    fi
    
    # Empfange und parse die Antwort
    local response=$(receive_message)
    if [[ -z "$response" ]]; then
        echo "FEHLER: Keine Antwort beim Lesen der Tabelle $table_id" >&2
        return 1
    fi
    
    parse_table_data "$response" "$table_id"
    return 0
}

# Hauptfunktion
function main {
    # CRC-Tabelle generieren
    echo "Generiere CRC-Tabelle..." >&2
    generate_crc_table
    
    # CSV-Header schreiben, wenn die Datei nicht existiert
    if [[ ! -f "$CSV_FILE" ]]; then
        echo "Timestamp,Fwd_active_energy_kWh,Rev_active_energy_kWh,Fwd_active_power_W,Rev_active_power_W,Import_Reactive_VAr,Export_Reactive_VAr,L1_current_A,L2_current_A,L3_current_A,L1_voltage_V,L2_voltage_V,L3_voltage_V" > "$CSV_FILE"
    fi
    
    while true; do
        echo "Starte neue Messung..." >&2
        
        # Initialisiere Verbindung
        if ! initialize_connection; then
            echo "FEHLER: Verbindungsaufbau fehlgeschlagen, versuche erneut in $POLL_INTERVAL Sekunden" >&2
            sleep $POLL_INTERVAL
            continue
        fi
        
        # Lese Tabelle 28 (aktuelle Werte)
        table28_data=$(read_table 28 0 40)
        
        # Lese Tabelle 23 (Energiezähler)
        table23_data=$(read_table 23 0 8)
        
        # Timestamp
        timestamp=$(date +"%Y-%m-%d %H:%M:%S")
        
        # In CSV schreiben
        echo "$timestamp,$table23_data$table28_data" >> "$CSV_FILE"
        
        # Verbindung beenden
        terminate_connection
        
        echo "Messung abgeschlossen, nächste Messung in $POLL_INTERVAL Sekunden" >&2
        sleep $POLL_INTERVAL
    done
}

# Skript starten
echo "Smart Meter OSGP Reader gestartet" >&2
main
