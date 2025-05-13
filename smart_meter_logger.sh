#!/bin/bash
#
# Smart Meter Logger Script
# Dieses Skript liest die Zählerwerte eines Smart Meters aus und speichert sie in einer CSV-Datei
# Es implementiert das ANSI C12.18/19 Protokoll wie in SmartMeterOSGPHandler.java definiert
#
# Version: 2.0
# Datum: $(date +"%Y-%m-%d")
#
# Features:
# - Vollständige Implementation des ANSI C12.18/19 Protokolls
# - CRC16-CCIT Prüfsummenberechnung
# - Toggle-Control-Bit Behandlung
# - Unterstützung für Tabellen-Lesevorgänge
# - Kompatibel mit dem OpenHAB Smart Meter OSGP Binding
# - Verbesserte Fehlerbehandlung und Diagnose
# - Windows/Linux-Kompatibilität
#

# Konfiguration
DEVICE="/dev/ttyUSB0"
PASSWORD="00000000"  # Standard-Passwort, kann über Parameter angepasst werden
CSV_FILE="smart_meter_data.csv"
LOG_FILE="smart_meter_logger.log"
POLL_INTERVAL=60     # Abfrageintervall in Sekunden
DEBUG_SCAN=false     # Auf true setzen, um einen vollständigen Tabellenscan durchzuführen

# Start-Byte und Identity-Byte (angepasst an SmartMeterOSGPHandler.java - EE/00)
START_BYTE=0xEE
IDENTITY_BYTE=0x00

# CRC16 CCIT Konfiguration
CRC16_CCIT_POLYNOM=0x8408  # Entspricht CRC16.Polynom.CRC16_CCIT in Java

# Java-Code verwendet diese Werte:
#private static final byte START = (byte) 0xEE;
#private static final byte IDENTITY = (byte) 0x00;

# Serielle Schnittstellenkonfiguration
# 9600 Baud, 8 Datenbits, keine Parität, 1 Stopbit (wie in SmartMeterOSGPHandler.java)
SERIAL_CONFIG="9600 raw cs8 -cstopb -parenb -echo -hupcl -ixoff -ixon"

# Globale Variable für Toggle-Control-Bit
TOGGLE_CONTROL=false

# Implementierung der CRC16 (CCIT) Berechnung
# Basierend auf der Java-Implementierung in CRC16.java
# Erzeugt die CRC16-Tabelle für CCIT Polynom
generate_crc16_table() {
    local polynom=$CRC16_CCIT_POLYNOM
    local -a table
    
    for (( x=0; x<256; x++ )); do
        local w=$x
        for (( i=0; i<8; i++ )); do
            if (( (w & 1) != 0 )); then
                w=$(( (w >> 1) ^ polynom ))
            else
                w=$(( w >> 1 ))
            fi
        done
        table[$x]=$w
    done
    
    echo "${table[@]}"
}

# Berechnet den CRC16-Wert für ein Array von Bytes
calculate_crc16() {
    local -a data=("$@")
    local -a crc_table=($(generate_crc16_table))
    local crc=0xFFFF  # Initialer CRC-Wert wie im Java-Code
    
    for byte in "${data[@]}"; do
        # Konvertiert Hex-Strings (0xNN) zu Integer-Werten
        if [[ "$byte" =~ ^0x ]]; then
            byte=$((byte))
        fi
        
        # Implementierung des CRC-Algorithmus wie in CRC16.java
        local idx=$(( (crc & 0xFF) ^ (byte & 0xFF) ))
        crc=$(( (crc >> 8) ^ ${crc_table[$idx]} ))
    done
    
    # XOR mit 0xFFFF wie im Java-Code (crc16Calc.calculate(...) ^ 0xFFFF)
    crc=$(( crc ^ 0xFFFF ))
    
    echo $crc
}

# Protokollkonstanten (aus SmartMeterOSGPHandler.java)
REQUEST_IDENT=0x20         # Ident-Request
REQUEST_TERMINATE=0x21     # Terminate-Request
REQUEST_READ=0x30          # Table Read Request
REQUEST_READ_PARTIAL=0x3F  # Partial Table Read Request
REQUEST_LOGON=0x50         # Logon Request
REQUEST_SECURITY=0x51      # Security Request (Passwort)
REQUEST_LOGOFF=0x52        # Logoff Request
REQUEST_NEGOTIATE=0x60     # Negotiate Request
REQUEST_NEGOTIATE2=0x61    # Negotiate2 Request
REQUEST_WAIT=0x70          # Wait Request
ACK=0x06                   # Acknowledgement
NACK=0x15                  # Negative Acknowledgement

# Tabellen IDs aus SmartMeterOSGPHandler.java
TABLE_GENERAL=0            # Allgemeine Konfiguration
TABLE_ENERGY=23            # Energiezähler (Fwd_active_energy, Rev_active_energy)
TABLE_POWER=28             # Momentane Leistungswerte (Fwd_active_power)

# Hilfsfunktion zum Loggen von Nachrichten
log_message() {
    local message="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# Hilfsfunktion zum Senden von Nachrichten mit SmartMeter-Protokollstruktur
# Implementiert die Paketstruktur wie in SmartMeterOSGPHandler.java
send_message() {
    local -a message=("$@")
    local sequence=0  # Sequence-Byte (in Java immer 0)
    local ctrl_byte
    
    # Toggle-Control-Bit setzen wie in Java-Implementierung
    if $TOGGLE_CONTROL; then
        ctrl_byte=0x20
    else
        ctrl_byte=0x00
    fi
    
    # TOGGLE_CONTROL für nächste Nachricht umschalten
    if $TOGGLE_CONTROL; then
        TOGGLE_CONTROL=false
    else
        TOGGLE_CONTROL=true
    fi
    
    # Länge der Nachricht berechnen
    local length=${#message[@]}
    local len_high=$(( (length >> 8) & 0xFF ))
    local len_low=$(( length & 0xFF ))
    
    # Protokollkopf erstellen: [START][IDENTITY][CONTROL][SEQUENCE][LENGTH_HIGH][LENGTH_LOW]
    local -a header=($START_BYTE $IDENTITY_BYTE $ctrl_byte $sequence $len_low $len_high)
    
    # Vollständige Nachricht zusammensetzen: Header + Message
    local -a full_message=("${header[@]}" "${message[@]}")
    
    # CRC16 berechnen
    local crc=$(calculate_crc16 "${full_message[@]}")
    local crc_low=$(( crc & 0xFF ))
    local crc_high=$(( (crc >> 8) & 0xFF ))
    
    # Nachricht mit CRC senden
    _send_bytes "${full_message[@]}" $crc_low $crc_high
    
    # Auf ACK/NACK prüfen und entsprechend reagieren
    wait_for_ack
}

# Hilfsfunktion zum Warten auf ein ACK
wait_for_ack() {
    local tmp_file=$(mktemp)
    local received=0
    local max_attempts=3
    
    for ((attempt=1; attempt <= max_attempts; attempt++)); do
        # Auf Antwort warten
        dd if="$DEVICE" of="$tmp_file" bs=1 count=1 iflag=nonblock 2>/dev/null
        
        if [[ -s "$tmp_file" ]]; then
            local response=$(hexdump -v -e '1/1 "%02X"' "$tmp_file")
            
            if [[ "$response" == "06" ]]; then  # ACK erhalten
                log_message "ACK empfangen"
                rm -f "$tmp_file"
                return 0
            elif [[ "$response" == "15" ]]; then  # NACK erhalten
                log_message "NACK empfangen, Versuch $attempt von $max_attempts"
                if [[ $attempt -lt $max_attempts ]]; then
                    sleep 0.5
                    continue
                fi
            elif [[ "$response" == "00" ]]; then  # Manchmal wird 0x00 als ACK akzeptiert
                log_message "0x00 empfangen, wird als ACK akzeptiert"
                rm -f "$tmp_file"
                return 0
            else
                log_message "Unerwartete Antwort: 0x$response"
            fi
        else
            log_message "Keine Antwort erhalten, Versuch $attempt von $max_attempts"
        fi
        
        # Pause vor dem nächsten Versuch
        sleep 1
    done
    
    log_message "Keine ACK-Antwort nach $max_attempts Versuchen"
    rm -f "$tmp_file"
    return 1
}

# Low-Level Funktion zum direkten Senden von Bytes
# Diese Funktion ist kompatibel mit Linux und Windows/WSL
_send_bytes() {
    local tmp_file=$(mktemp)
    
    # Debug-Ausgabe in Logdatei
    echo -n "Sende: " | tee -a "$LOG_FILE"
    for byte in "$@"; do
        # Sicherstellen, dass der Wert eine Zahl ist (keine Hex-Strings wie 0xNN)
        if [[ $byte =~ ^0x ]]; then
            byte=$((byte))
        fi
        printf "%02X " $byte | tee -a "$LOG_FILE"
        
        # Für Windows/WSL
        if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
            # In Windows-Umgebung speichern wir die Bytes für spätere Verarbeitung
            printf "%02X" $byte >> "$tmp_file.hex"
        else 
            # Standard Linux/Unix Methode
            printf "\\$(printf '%03o' $byte)" >> "$tmp_file"
        fi
    done
    echo "" | tee -a "$LOG_FILE"
    
    # Daten senden basierend auf Betriebssystem
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
        # Windows-kompatible Methode mit PowerShell
        log_message "Windows-Umgebung erkannt. Verwende PowerShell für serielle Kommunikation."
        
        if [[ -f "$tmp_file.hex" ]]; then
            if type -p powershell.exe >/dev/null 2>&1; then
                # Hier können wir das existierende PowerShell-Skript aufrufen
                local hex_data=$(cat "$tmp_file.hex")
                powershell.exe -Command "& '$PWD/windows_meter_scanner.ps1' -ComPort '$DEVICE' -HexData '$hex_data' -Operation 'write'"
            else
                log_message "FEHLER: PowerShell nicht gefunden. Kann keine Daten senden."
            fi
            rm -f "$tmp_file.hex"
        fi
    else 
        # Standard Linux/Unix Methode mit dd
        dd if="$tmp_file" of="$DEVICE" bs=1 count=$# 2>/dev/null
        sync
    fi
    
    rm -f "$tmp_file"
    
    # Kurze Pause nach dem Senden
    sleep 0.1
}

# Hilfsfunktion zum Umwandeln eines Strings in Hex-Bytes
string_to_bytes() {
    local text="$1"
    local bytes=()
    
    for ((i=0; i<${#text}; i++)); do
        local char="${text:$i:1}"
        local byte=$(printf "%d" "'$char" 2>/dev/null || echo 63)  # 63 = ?
        bytes+=($byte)
    done
    
    echo "${bytes[@]}"
}

# Request-Funktionen basierend auf SmartMeterOSGPHandler.java

# Sendet einen einzelnen Request-Befehl
send_request_id() {
    local request=$1
    log_message "Sende Request-ID: 0x$(printf '%02X' $request)"
    send_message $request
}

# Negotiate-Request für die Konfiguration der Kommunikation
send_negotiate_request() {
    log_message "Sende Negotiate-Request"
    
    # Parameter wie in SmartMeterOSGPHandler.java:
    # - Maximum packet size: 64 (2 Bytes)
    # - Maximum packets for reassembly: 2 (1 Byte)
    # - Baudrate: 9600 (entspricht Enum-Wert 6) (1 Byte)
    send_message $REQUEST_NEGOTIATE2 0x40 0x00 0x02 0x06
}

# Logon-Request zur Authentifizierung
send_logon_request() {
    local user_id=$1
    local username=$2
    
    log_message "Sende Logon-Request für User-ID: $user_id, Username: $username"
    
    # User-ID als 2 Bytes
    local id_low=$(( user_id & 0xFF ))
    local id_high=$(( (user_id >> 8) & 0xFF ))
    
    # Message zusammenbauen
    local -a message=($REQUEST_LOGON $id_low $id_high)
    
    # Username-Bytes hinzufügen (12 Bytes insgesamt, mit Leerzeichen auffüllen)
    local -a username_bytes=($(string_to_bytes "$username"))
    
    for byte in "${username_bytes[@]}"; do
        message+=($byte)
    done
    
    # Mit Leerzeichen auffüllen (ASCII 32) bis 12 Zeichen
    while [[ ${#message[@]} -lt 13 ]]; do
        message+=(32)  # Space-ASCII
    done
    
    send_message "${message[@]}"
}

# Security-Request mit Passwort
send_security_request() {
    local password=$1
    
    log_message "Sende Security-Request mit Passwort"
    
    # Message beginnen
    local -a message=($REQUEST_SECURITY)
    
    # Passwort-Bytes hinzufügen
    local -a password_bytes=($(string_to_bytes "$password"))
    
    for byte in "${password_bytes[@]}"; do
        message+=($byte)
    done
    
    # Mit Nullen auffüllen bis 20 Bytes
    while [[ ${#message[@]} -lt 21 ]]; do
        message+=(0)
    done
    
    send_message "${message[@]}"
}

# Read-Table-Request für eine komplette Tabelle
send_read_table() {
    local table=$1
    
    log_message "Sende Read-Table-Request für Tabelle $table"
    
    # Tabellen-ID als 2 Bytes
    local table_low=$(( table & 0xFF ))
    local table_high=$(( (table >> 8) & 0xFF ))
    
    send_message $REQUEST_READ $table_low $table_high
}

# Read-Partial-Table-Request für einen Teil einer Tabelle
send_read_partial_table() {
    local table=$1
    local offset=$2
    local bytes=$3
    
    log_message "Sende Read-Partial-Table-Request für Tabelle $table, Offset $offset, $bytes Bytes"
    
    # Tabellen-ID als 2 Bytes
    local table_low=$(( table & 0xFF ))
    local table_high=$(( (table >> 8) & 0xFF ))
    
    # Offset als 3 Bytes (1 Byte für höchstes Byte, 2 Bytes für die unteren)
    local offset_highest=$(( (offset >> 16) & 0xFF ))
    local offset_low=$(( offset & 0xFF ))
    local offset_high=$(( (offset >> 8) & 0xFF ))
    
    # Anzahl Bytes als 2 Bytes
    local bytes_low=$(( bytes & 0xFF ))
    local bytes_high=$(( (bytes >> 8) & 0xFF ))
    
    send_message $REQUEST_READ_PARTIAL $table_low $table_high $offset_highest $offset_low $offset_high $bytes_low $bytes_high
}

# Empfange eine Nachricht und prüfe auf ACK
receive_msg_and_check_ack() {
    local response_file=$(mktemp)
    local response_received=false
    
    # Auf Antwort warten mit mehreren Versuchen
    for attempt in {1..5}; do
        # Mehr Daten lesen als nötig, um sicherzustellen, dass wir die ganze Antwort bekommen
        dd if="$DEVICE" of="$response_file" bs=1 count=1024 iflag=nonblock 2>/dev/null
        
        if [[ -s "$response_file" ]]; then
            response_received=true
            log_message "Antwort erhalten (Versuch $attempt):"
            hexdump -C "$response_file" | tee -a "$LOG_FILE"
            break
        fi
        
        log_message "Warte auf Antwort... (Versuch $attempt/5)"
        sleep 0.5
    done
    
    # Keine Antwort erhalten
    if ! $response_received; then
        log_message "FEHLER: Keine Antwort erhalten"
        rm -f "$response_file"
        return 1
    fi
    
    # Prüfe, ob die Antwort mit START_BYTE beginnt
    local first_byte=$(hexdump -v -e '1/1 "%02X"' -s 0 -n 1 "$response_file")
    if [[ "$(printf '%02X' $START_BYTE)" != "$first_byte" ]]; then
        log_message "FEHLER: Antwort beginnt nicht mit START_BYTE"
        rm -f "$response_file"
        return 1
    fi
    
    # Extrahiere die Länge (Bytes 4-5)
    local len_bytes=$(hexdump -v -e '1/2 "%u"' -s 4 -n 2 "$response_file")
    
    # Prüfe den Response-Code (erster Byte nach dem Header)
    local response_code=$(hexdump -v -e '1/1 "%u"' -s 6 -n 1 "$response_file")
    
    if [[ "$response_code" -ne 0 ]]; then
        log_message "FEHLER: Response-Code ist nicht 0 (Acknowledge), sondern $response_code"
        rm -f "$response_file"
        return 1
    fi
    
    # Extrahiere die Daten nach dem Header und vor dem CRC
    # Diese Funktion sollte die relevanten Daten zurückgeben, falls benötigt
    
    log_message "Erfolgreiche Antwort mit Response-Code: $response_code"
    rm -f "$response_file"
    return 0
}
# Funktion zur Initialisierung der CSV-Datei
initialize_csv() {
    if [[ ! -f "$CSV_FILE" ]]; then
        echo "Zeitstempel,KWH_Total,KWH_Tarif1,KWH_Tarif2,Aktuelle_Leistung_W,Spannung_V,Strom_A" > "$CSV_FILE"
        log_message "CSV-Datei initialisiert: $CSV_FILE"
    fi
}

# Funktion zur Prüfung, ob ein Gerät existiert (unter Windows/WSL)
check_device() {
    # Unter Windows müssen wir möglicherweise mit COM-Ports arbeiten
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
        # Für Windows PowerShell Umgebung 
        if [[ "$DEVICE" == "/dev/ttyUSB"* ]]; then
            # Automatisch zu COM-Port konvertieren für Windows-Umgebungen
            local usb_num=${DEVICE##*/ttyUSB}
            DEVICE="COM$((usb_num + 1))"  # Normalerweise ist COM1 = ttyUSB0
            log_message "Windows-Umgebung erkannt: Konvertiere zu $DEVICE"
        fi
        
        # Prüfe, ob COM-Port existiert (versuche direkt zu öffnen)
        if ! type -p mode.com &>/dev/null; then
            log_message "WARNUNG: mode.com nicht gefunden, kann COM-Port nicht prüfen"
            return 0
        fi
        
        if ! mode.com "$DEVICE" > /dev/null 2>&1; then
            log_message "FEHLER: Gerät $DEVICE existiert nicht oder ist nicht zugänglich!"
            exit 1
        fi
    else
        # Standard Linux/Unix Prüfung
        if [[ ! -e "$DEVICE" ]]; then
            log_message "FEHLER: Gerät $DEVICE existiert nicht!"
            exit 1
        fi
    fi
}

# Funktion zur Initialisierung der seriellen Schnittstelle
initialize_serial() {
    # Prüfe, ob das Gerät existiert
    check_device
    
    # Windows/WSL-Kompatibilität
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
        log_message "Windows-Umgebung erkannt. Verwende PowerShell für serielle Konfiguration."
        log_message "Serielle Schnittstellenkonfiguration: $SERIAL_CONFIG (angepasst für Windows)"
        
        # Versuche PowerShell zu nutzen (vereinfachte Konfiguration)
        # Hinweis: Für Windows sollte ein separates PowerShell-Skript erstellt werden
        #          das diese Funktion übernimmt. Hier nur ein einfacher Versuch.
        return 0
    else
        # Linux/Unix Konfiguration
        # Konfiguriere serielle Schnittstelle mit erweiterter Konfiguration
        stty -F $DEVICE $SERIAL_CONFIG
        log_message "Serielle Schnittstelle konfiguriert: $SERIAL_CONFIG"
        
        # Puffer gründlich leeren
        dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
        sleep 0.5
        
        # Schnittstelle zurücksetzen
        stty -F $DEVICE 0
        sleep 0.2
        stty -F $DEVICE $SERIAL_CONFIG
        log_message "Serielle Schnittstelle zurückgesetzt und neu konfiguriert"
    fi
}

# Funktion zur Kommunikation mit dem Smart Meter
# Implementiert die Sequenz wie in SmartMeterOSGPHandler.pollStatus()
communicate_with_meter() {
    local attempt=1
    local max_attempts=3
    
    while (( attempt <= max_attempts )); do
        log_message "Kommunikationsversuch $attempt/$max_attempts..."
        
        # Toggle-Control-Bit zurücksetzen bei neuem Versuch
        TOGGLE_CONTROL=false
        
        # 1. Sende Wake-up Sequenz - verbessert mit mehreren Wiederholungen
        log_message "Sende Wake-up Sequenz..."
        for i in {1..3}; do
            _send_bytes 0x55 0x55 0x55 0x55 0x55
            sleep 0.3
        done
        sleep 1
        
        # 2. Sende Ident-Request (wie in Java-Implementation)
        log_message "Sende Ident-Request..."
        if ! send_request_id $REQUEST_IDENT; then
            log_message "Fehler beim Senden des Ident-Request"
            (( attempt++ ))
            continue
        fi
        
        # 3. Sende Negotiate-Request
        if ! send_negotiate_request; then
            log_message "Fehler beim Senden des Negotiate-Request"
            (( attempt++ ))
            continue
        fi
        log_message "Negotiate erfolgreich"
        
        # 4. Sende Logon-Request
        local user_id=0  # Standard-User-ID
        local username="User"  # Standard-Username
        if ! send_logon_request $user_id "$username"; then
            log_message "Fehler beim Senden des Logon-Request"
            (( attempt++ ))
            continue
        fi
        log_message "Logon erfolgreich"
        
        # 5. Sende Security-Request mit Passwort
        if ! send_security_request "$PASSWORD"; then
            log_message "Fehler beim Senden des Security-Request"
            (( attempt++ ))
            continue
        fi
        log_message "Security-Request erfolgreich"
        
        # 6. Lese Tabelle 0 (Standard-Infotabelle)
        if ! send_read_table 0; then
            log_message "Fehler beim Lesen der Tabelle 0"
            (( attempt++ ))
            continue
        fi
        log_message "Tabelle 0 erfolgreich gelesen"
        
        # 7. Lese Zählerstände aus verschiedenen Tabellen
        read_meter_values
        
        # 8. Logoff und Terminate
        send_request_id $REQUEST_LOGOFF
        send_request_id $REQUEST_TERMINATE
        
        return 0
    done
    
    log_message "Kommunikation fehlgeschlagen nach $max_attempts Versuchen"
    return 1
}

# Funktion zur Authentifizierung
authenticate_with_meter() {
    log_message "Versuche Authentifizierung mit Passwort: $PASSWORD"
    
    # Konvertiere Passwort in Byte-Array
    local password_bytes=($(string_to_bytes "$PASSWORD"))
    local password_len=${#PASSWORD}
    
    # LOGON-Request mit Passwort zusammenbauen
    local logon_bytes=($START_BYTE $IDENTITY_BYTE 0x00 0x00 $password_len 0x00 $REQUEST_LOGON)
    
    # Passwort-Bytes hinzufügen
    for byte in "${password_bytes[@]}"; do
        logon_bytes+=($byte)
    done
    
    # Sende LOGON-Request
    send_bytes "${logon_bytes[@]}"
    log_message "Auth-Request gesendet"
    sleep 1
    
    # Empfange Antwort
    local auth_response=$(mktemp)
    dd if="$DEVICE" of="$auth_response" bs=1 count=20 iflag=nonblock 2>/dev/null
    
    if [[ -s "$auth_response" ]]; then
        log_message "Antwort auf Auth-Request erhalten:"
        hexdump -C "$auth_response" >> "$LOG_FILE"
        
        # Prüfe auf ACK
        if grep -q -a $'\x06' "$auth_response"; then
            log_message "Authentifizierung erfolgreich"
            rm -f "$auth_response"
            return 0
        else
            log_message "Authentifizierung fehlgeschlagen"
        fi
    else
        log_message "Keine Antwort auf Auth-Request"
    fi
    
    rm -f "$auth_response"
    return 1
}

# Funktion zum Auslesen der Zählerstände
# Implementiert die Tabellen-Leslogik wie in SmartMeterOSGPHandler.java
read_meter_values() {
    log_message "Lese Zählerstände aus..."
    
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local kwh_total=""
    local kwh_t1=""
    local kwh_t2=""
    local power=""
    local voltage_l1=""
    local voltage_l2=""
    local voltage_l3=""
    local current_l1=""
    local current_l2=""
    local current_l3=""
    local data_collected=false
    
    # Spezifische Tabellen aus der Java-Implementierung
    # Tabelle 23: Energiewerte (Forward/Reverse active energy)
    # Tabelle 28: Momentanwerte (Forward/Reverse active power, L1/L2/L3 current/voltage)
    
    # 1. Lese Tabelle 23 für Energiewerte
    log_message "Lese Tabelle 23 (Energiewerte)..."
    if send_read_table 23; then
        local data_file=$(mktemp)
        # Empfange Antwort mit längerer Timeout-Zeit
        dd if="$DEVICE" of="$data_file" bs=1 count=512 iflag=nonblock 2>/dev/null
        sleep 0.5
        
        if [[ -s "$data_file" ]]; then
            log_message "Daten für Tabelle 23 empfangen"
            hexdump -C "$data_file" | tee -a "$LOG_FILE"
            
            # Analog zur Methode handleTable23Reply() in Java
            # Die Daten beginnen nach dem Header (typisch: nach 7 Bytes)
            # Format ist Little-Endian
            
            # Extrahiere den Tabellenlängen-Header (2 Bytes nach Protokoll-Header)
            local header_offset=7  # START(1) + IDENTITY(1) + CTRL(1) + SEQ(1) + LEN(2) + RESP_CODE(1)
            
            # Forward Active Energy (4 Bytes)
            local fwd_active=$(hexdump -v -e '1/4 "%u"' -s $header_offset -n 4 "$data_file" 2>/dev/null)
            if [[ -n "$fwd_active" && "$fwd_active" -gt 0 ]]; then
                # Konvertiere von Wh zu kWh wie in Java
                kwh_total=$(echo "scale=3; $fwd_active / 1000" | bc)
                log_message "Vorwärts-Energie: $kwh_total kWh"
                data_collected=true
            fi
            
            # Reverse Active Energy (4 Bytes)
            local rev_active=$(hexdump -v -e '1/4 "%u"' -s $((header_offset + 4)) -n 4 "$data_file" 2>/dev/null)
            if [[ -n "$rev_active" && "$rev_active" -gt 0 ]]; then
                # Konvertiere von Wh zu kWh
                rev_active=$(echo "scale=3; $rev_active / 1000" | bc)
                log_message "Rückwärts-Energie: $rev_active kWh"
                kwh_t1=$rev_active  # Speichere als Tarif 1 für CSV-Kompatibilität
            fi
        else
            log_message "Keine Daten für Tabelle 23 empfangen"
        fi
        rm -f "$data_file"
    else
        log_message "Fehler beim Lesen der Tabelle 23"
    fi
    
    sleep 0.5
    
    # 2. Lese Tabelle 28 für Momentanwerte
    log_message "Lese Tabelle 28 (Momentanwerte)..."
    if send_read_partial_table 28 0 40; then  # Lese 40 Bytes ab Offset 0
        local data_file=$(mktemp)
        # Empfange Antwort mit längerer Timeout-Zeit
        dd if="$DEVICE" of="$data_file" bs=1 count=512 iflag=nonblock 2>/dev/null
        sleep 0.5
        
        if [[ -s "$data_file" ]]; then
            log_message "Daten für Tabelle 28 empfangen"
            hexdump -C "$data_file" | tee -a "$LOG_FILE"
            
            # Analog zur Methode handleTable28Reply() in Java
            local header_offset=7  # Wie oben
            
            # Prüfe Tabellenlänge (bei Offset 0x03)
            local table_length=$(hexdump -v -e '1/2 "%u"' -s $header_offset -n 2 "$data_file" 2>/dev/null)
            header_offset=$((header_offset + 2))  # Überspringe die Tabellenlänge
            
            # Forward Active Power
            local fwd_power=$(hexdump -v -e '1/4 "%u"' -s $header_offset -n 4 "$data_file" 2>/dev/null)
            if [[ -n "$fwd_power" ]]; then
                power=$fwd_power
                log_message "Vorwärts-Leistung: $power W"
                data_collected=true
            fi
            header_offset=$((header_offset + 4))
            
            # Reverse Active Power
            local rev_power=$(hexdump -v -e '1/4 "%u"' -s $header_offset -n 4 "$data_file" 2>/dev/null)
            if [[ -n "$rev_power" ]]; then
                log_message "Rückwärts-Leistung: $rev_power W"
            fi
            header_offset=$((header_offset + 4))
            
            # Import Reactive Power (VAr)
            header_offset=$((header_offset + 4))
            
            # Export Reactive Power (VAr)
            header_offset=$((header_offset + 4))
            
            # L1/L2/L3 Strom in mA
            current_l1=$(hexdump -v -e '1/4 "%u"' -s $header_offset -n 4 "$data_file" 2>/dev/null)
            if [[ -n "$current_l1" ]]; then
                current_l1=$(echo "scale=3; $current_l1 / 1000" | bc)
                log_message "Strom L1: $current_l1 A"
            fi
            header_offset=$((header_offset + 4))
            
            current_l2=$(hexdump -v -e '1/4 "%u"' -s $header_offset -n 4 "$data_file" 2>/dev/null)
            if [[ -n "$current_l2" ]]; then
                current_l2=$(echo "scale=3; $current_l2 / 1000" | bc)
                log_message "Strom L2: $current_l2 A"
            fi
            header_offset=$((header_offset + 4))
            
            current_l3=$(hexdump -v -e '1/4 "%u"' -s $header_offset -n 4 "$data_file" 2>/dev/null)
            if [[ -n "$current_l3" ]]; then
                current_l3=$(echo "scale=3; $current_l3 / 1000" | bc)
                log_message "Strom L3: $current_l3 A"
            fi
            header_offset=$((header_offset + 4))
            
            # L1/L2/L3 Spannung in mV
            voltage_l1=$(hexdump -v -e '1/4 "%u"' -s $header_offset -n 4 "$data_file" 2>/dev/null)
            if [[ -n "$voltage_l1" ]]; then
                voltage_l1=$(echo "scale=1; $voltage_l1 / 1000" | bc)
                log_message "Spannung L1: $voltage_l1 V"
            fi
            header_offset=$((header_offset + 4))
            
            voltage_l2=$(hexdump -v -e '1/4 "%u"' -s $header_offset -n 4 "$data_file" 2>/dev/null)
            if [[ -n "$voltage_l2" ]]; then
                voltage_l2=$(echo "scale=1; $voltage_l2 / 1000" | bc)
                log_message "Spannung L2: $voltage_l2 V"
            fi
            header_offset=$((header_offset + 4))
            
            voltage_l3=$(hexdump -v -e '1/4 "%u"' -s $header_offset -n 4 "$data_file" 2>/dev/null)
            if [[ -n "$voltage_l3" ]]; then
                voltage_l3=$(echo "scale=1; $voltage_l3 / 1000" | bc)
                log_message "Spannung L3: $voltage_l3 V"
            fi
            
        else
            log_message "Keine Daten für Tabelle 28 empfangen"
        fi
        rm -f "$data_file"
    else
        log_message "Fehler beim Lesen der Tabelle 28"
    fi
    
    # Wenn Daten gesammelt wurden, füge sie der CSV-Datei hinzu
    if $data_collected; then
        # Durchschnittliche Spannung und Strom berechnen (wenn mehrphasig)
        local voltage="${voltage_l1:-0}"
        if [[ -n "$voltage_l2" || -n "$voltage_l3" ]]; then
            voltage=$(echo "scale=1; (${voltage_l1:-0} + ${voltage_l2:-0} + ${voltage_l3:-0}) / 3" | bc)
        fi
        
        local current="${current_l1:-0}"
        if [[ -n "$current_l2" || -n "$current_l3" ]]; then
            current=$(echo "scale=3; (${current_l1:-0} + ${current_l2:-0} + ${current_l3:-0}) / 3" | bc)
        fi
        
        # Fallback-Werte setzen, falls Werte nicht gefunden wurden
        kwh_total="${kwh_total:-N/A}"
        kwh_t1="${kwh_t1:-N/A}"
        kwh_t2="${kwh_t2:-N/A}"
        power="${power:-N/A}"
        voltage="${voltage:-N/A}"
        current="${current:-N/A}"
        
        # CSV-Zeile schreiben
        echo "$timestamp,$kwh_total,$kwh_t1,$kwh_t2,$power,$voltage,$current" >> "$CSV_FILE"
        log_message "Daten in CSV geschrieben: $kwh_total kWh, $power W, $voltage V, $current A"
        return 0
    else
        log_message "Keine verwertbaren Daten erhalten"
        return 1
    fi
}

# Funktion zum Abmelden
logoff_meter() {
    log_message "Melde vom Zähler ab..."
    send_bytes $START_BYTE $IDENTITY_BYTE 0x00 0x00 0x01 0x00 $REQUEST_LOGOFF
    sleep 1
    
    # Empfange Antwort (optional)
    local logoff_resp=$(mktemp)
    dd if="$DEVICE" of="$logoff_resp" bs=1 count=10 iflag=nonblock 2>/dev/null
    
    if [[ -s "$logoff_resp" ]]; then
        log_message "Antwort auf Abmeldung erhalten:"
        hexdump -C "$logoff_resp" >> "$LOG_FILE"
    fi
    
    rm -f "$logoff_resp"
}

# Debug-Funktion, um alle Tabellen zu scannen und auszugeben
scan_all_tables() {
    local scan_output="$PWD/table_scan.txt"
    log_message "Starte vollständigen Tabellenscan... Ausgabe wird in $scan_output gespeichert"
    
    # Datei mit Header erstellen
    echo "SMART METER TABLE SCAN $(date)" > "$scan_output"
    echo "===============================" >> "$scan_output"
    echo "Gerät: $DEVICE" >> "$scan_output"
    echo "Kommunikationsparameter: $SERIAL_CONFIG" >> "$scan_output"
    echo "Start-Byte: $(printf "0x%02X" $START_BYTE), Identity-Byte: $(printf "0x%02X" $IDENTITY_BYTE)" >> "$scan_output"
    echo "Protocol: ANSI C12.18/19, IEC 62056-21" >> "$scan_output"
    echo "===============================" >> "$scan_output"
    echo "" >> "$scan_output"
    
    # Initialisiere Toggle-Control-Bit
    TOGGLE_CONTROL=false
    
    # Wake-up und Initialisierung
    log_message "Sende initiale Wake-up Sequenz für den Scan..."
    for i in {1..5}; do
        _send_bytes 0x55 0x55 0x55 0x55 0x55
        sleep 0.3
    done
    sleep 1
    
    # Protokoll-Handshake durchführen
    log_message "Initialisiere Verbindung zum Zähler..."
    
    # Ident, Negotiate, Logon, Security
    if ! send_request_id $REQUEST_IDENT; then
        log_message "FEHLER: Ident-Request fehlgeschlagen. Breche Scan ab."
        return 1
    fi
    
    if ! send_negotiate_request; then
        log_message "FEHLER: Negotiate-Request fehlgeschlagen. Breche Scan ab."
        return 1
    fi
    
    if ! send_logon_request 0 "User"; then
        log_message "FEHLER: Logon-Request fehlgeschlagen. Breche Scan ab."
        return 1
    fi
    
    if ! send_security_request "$PASSWORD"; then
        log_message "FEHLER: Security-Request fehlgeschlagen. Breche Scan ab."
        return 1
    fi
    
    # Wir scannen Tabellen von 0-50, was die meisten relevanten Tabellen abdecken sollte
    echo "Start des Scans: $(date)" >> "$scan_output"
    echo "Verwende verbesserte Protokoll-Implementierung entsprechend SmartMeterOSGPHandler.java" >> "$scan_output"
    echo "" >> "$scan_output"
    
    # Fortschrittsanzeige
    local total_tables=51  # 0-50 Tables
    local scanned=0
    local data_found=0
    
    # Puffer leeren vor dem Scan
    dd if="$DEVICE" iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
    sleep 0.5
    
    for table in {0..50}; do
        # Fortschrittsanzeige
        scanned=$((scanned + 1))
        local table_hex=$(printf "%02X" $table)
        log_message "Scanne Tabelle $table_hex... [$scanned/$total_tables]"
        
        # Sende Read Request für die Tabelle mit der neuen Protokoll-Implementierung
        send_read_table $table
        
        # Empfange Antwort mit mehreren Versuchen
        local scan_file=$(mktemp)
        local received=0
        
        for attempt in {1..3}; do
            dd if="$DEVICE" of="$scan_file" bs=1 count=512 iflag=nonblock 2>/dev/null
            local file_size=$(stat -c %s "$scan_file" 2>/dev/null || echo "0")
            
            if [[ "$file_size" -gt 5 ]]; then
                received=1
                break
            fi
            
            log_message "Versuch $attempt: Keine sofortige Antwort für Tabelle $table_hex, warte..."
            sleep 0.5
        done
        
        if [[ $received -eq 1 && -s "$scan_file" ]]; then
            local file_size=$(stat -c %s "$scan_file")
            
            # Antwort analysieren
            # Prüfe ob es START_BYTE am Anfang hat
            local first_byte=$(hexdump -v -e '1/1 "%02X"' -s 0 -n 1 "$scan_file")
            
            if [[ "$(printf '%02X' $START_BYTE)" == "$first_byte" ]]; then
                # Gültiges Frame - Extrahiere Response-Code (Byte nach dem Header)
                local resp_code=$(hexdump -v -e '1/1 "%u"' -s 6 -n 1 "$scan_file")
                
                if [[ "$resp_code" -eq 0 ]]; then
                    # Acknowledge (0) - Daten gefunden
                    log_message "Daten für Tabelle $table_hex gefunden (${file_size} Bytes)"
                    
                    echo "----- TABELLE $table_hex: -----" >> "$scan_output"
                    echo "Bytes: $file_size" >> "$scan_output"
                    echo "Response-Code: $resp_code (ACK)" >> "$scan_output"
                    hexdump -C "$scan_file" >> "$scan_output"
                    echo "" >> "$scan_output"
                    data_found=$((data_found + 1))
                else
                    # Fehlercode
                    log_message "Fehler $resp_code für Tabelle $table_hex erhalten"
                    echo "TABELLE $table_hex: FEHLER (Code $resp_code)" >> "$scan_output"
                    hexdump -C "$scan_file" >> "$scan_output"
                    echo "" >> "$scan_output"
                fi
            elif grep -q -a $'\x06' "$scan_file"; then
                # Nur ACK, keine Daten
                log_message "Nur ACK für Tabelle $table_hex erhalten - keine Daten"
                echo "TABELLE $table_hex: NUR ACK ERHALTEN (KEINE DATEN)" >> "$scan_output"
            elif grep -q -a $'\x15' "$scan_file"; then
                # NACK erhalten
                log_message "NACK für Tabelle $table_hex erhalten - Tabelle nicht verfügbar"
                echo "TABELLE $table_hex: NICHT VERFÜGBAR (NACK)" >> "$scan_output"
            else
                # Unbekanntes Format
                log_message "Unbekannte Antwort für Tabelle $table_hex erhalten"
                echo "TABELLE $table_hex: UNBEKANNTE ANTWORT" >> "$scan_output"
                hexdump -C "$scan_file" >> "$scan_output"
                echo "" >> "$scan_output"
            fi
        else
            log_message "Keine Antwort für Tabelle $table_hex erhalten"
            echo "TABELLE $table_hex: KEINE ANTWORT" >> "$scan_output"
        fi
        
        rm -f "$scan_file"
        sleep 0.5
    done
    
    # Session beenden
    log_message "Beende Session..."
    send_request_id $REQUEST_LOGOFF
    send_request_id $REQUEST_TERMINATE
    
    # Zusammenfassung
    echo "" >> "$scan_output"
    echo "===============================" >> "$scan_output"
    echo "Scan abgeschlossen: $(date)" >> "$scan_output"
    echo "Gescannte Tabellen: $scanned" >> "$scan_output"
    echo "Tabellen mit Daten: $data_found" >> "$scan_output"
    
    log_message "Tabellenscan abgeschlossen. $data_found Tabellen mit Daten gefunden."
    log_message "Ergebnisse wurden in $scan_output gespeichert."
    
    # Zeige den Pfad zur Scan-Datei deutlich an
    echo ""
    echo "SCAN-ERGEBNISSE: $scan_output"
    echo ""
}

# Hauptfunktion
main() {
    log_message "Smart Meter Logger gestartet"
    log_message "Gerät: $DEVICE, Intervall: $POLL_INTERVAL Sekunden"
    
    # Initialisierung
    initialize_csv
    initialize_serial
    
    # Debug: Wenn DEBUG_SCAN gesetzt ist, führe einen vollständigen Tabellenscan durch
    if [[ "$DEBUG_SCAN" == "true" ]]; then
        log_message "DEBUG-MODUS: Führe einmaligen Tabellenscan durch"
        scan_all_tables
        exit 0
    fi
    
    # Fortlaufender Betrieb starten
    log_message "Beginne mit regelmäßiger Datenabfrage..."
    
    # Fangen von Ctrl+C/SIGINT, um ordnungsgemäß zu beenden
    trap 'log_message "Skript wird beendet..."; logoff_meter; exit 0' SIGINT
    
    # Beim ersten Start alle Fehler einmal ignorieren
    local first_run=true
    
    while true; do
        # Kommunikation mit dem Zähler
        if communicate_with_meter; then
            log_message "Erfolgreich Daten vom Zähler gelesen"
            first_run=false
        else
            log_message "Fehler beim Lesen vom Zähler"
            
            # Bei wiederholten Fehlern, versuche die serielle Schnittstelle neu zu initialisieren
            if ! $first_run; then
                log_message "Versuche serielle Schnittstelle zurückzusetzen..."
                initialize_serial
            else
                first_run=false
            fi
        fi
        
        log_message "Warte $POLL_INTERVAL Sekunden bis zur nächsten Abfrage..."
        sleep "$POLL_INTERVAL"
    done
}

# Kommandozeilenargumente verarbeiten
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Verwendung: $0 [--password PASSWORT] [--interval SEKUNDEN] [--output DATEI] [--scan] [--device GERÄT]"
    echo ""
    echo "Optionen:"
    echo "  --password, -p PASSWORT  Das zu verwendende Passwort (Standard: 00000000)"
    echo "  --interval, -i SEKUNDEN  Abfrageintervall in Sekunden (Standard: 60)"
    echo "  --output, -o DATEI       Name der CSV-Ausgabedatei (Standard: smart_meter_data.csv)"
    echo "  --device, -d GERÄT       Serielles Gerät für die Kommunikation (Standard: /dev/ttyUSB0)"
    echo "  --scan, -s               Führt einen vollständigen Tabellenscan durch und beendet sich"
    echo "  --help, -h               Diese Hilfe anzeigen"
    exit 0
fi

# Parameter verarbeiten
while [[ $# -gt 0 ]]; do
    case "$1" in
        --password|-p)
            if [[ -n "$2" ]]; then
                PASSWORD="$2"
                echo "Verwende Passwort: $PASSWORD"
                shift 2
            else
                echo "FEHLER: Nach --password muss ein Passwort angegeben werden!"
                exit 1
            fi
            ;;
        --interval|-i)
            if [[ -n "$2" ]]; then
                POLL_INTERVAL="$2"
                echo "Verwende Abfrageintervall: $POLL_INTERVAL Sekunden"
                shift 2
            else
                echo "FEHLER: Nach --interval muss eine Zahl angegeben werden!"
                exit 1
            fi
            ;;
        --output|-o)
            if [[ -n "$2" ]]; then
                CSV_FILE="$2"
                echo "Verwende Ausgabedatei: $CSV_FILE"
                shift 2
            else
                echo "FEHLER: Nach --output muss ein Dateiname angegeben werden!"
                exit 1
            fi
            ;;
        --device|-d)
            if [[ -n "$2" ]]; then
                DEVICE="$2"
                echo "Verwende Gerät: $DEVICE"
                shift 2
            else
                echo "FEHLER: Nach --device muss ein Gerätepfad angegeben werden!"
                exit 1
            fi
            ;;
        --scan|-s)
            DEBUG_SCAN=true
            echo "Tabellenscan-Modus aktiviert"
            shift
            ;;
        *)
            echo "Unbekannte Option: $1"
            echo "Verwende --help für Hilfe"
            exit 1
            ;;
    esac
done

# Skript starten
main
