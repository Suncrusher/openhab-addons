#!/bin/bash
#
# Smart Meter Logger Script
# Dieses Skript liest die Zählerwerte eines Smart Meters aus und speichert sie in einer CSV-Datei
# Es nutzt die zuvor gefundene erfolgreiche Konfiguration: Start-Byte 0x01, Identity-Byte 0x3F
#
# Version: 1.0
# Datum: $(date +"%Y-%m-%d")
#

# Konfiguration
DEVICE="/dev/ttyUSB0"
PASSWORD="00000000"  # Standard-Passwort, kann über Parameter angepasst werden
CSV_FILE="smart_meter_data.csv"
LOG_FILE="smart_meter_logger.log"
POLL_INTERVAL=60     # Abfrageintervall in Sekunden

# Start-Byte und Identity-Byte aus der erfolgreichen Konfiguration
START_BYTE=0x01
IDENTITY_BYTE=0x3F

# Serielle Schnittstellenkonfiguration (aus erfolgreichem Test)
SERIAL_CONFIG="9600 raw cs8 cstopb -parenb -echo -hupcl"

# Protokollkonstanten
REQUEST_IDENT=0x20      # Ident-Request
REQUEST_READ=0x30       # Table Read Request
REQUEST_READ_PARTIAL=0x3F  # Partial Table Read Request
REQUEST_LOGON=0x50      # Logon Request
REQUEST_LOGOFF=0x52     # Logoff Request
ACK=0x06               # Acknowledgement
NACK=0x15              # Negative Acknowledgement

# Hilfsfunktion zum Loggen von Nachrichten
log_message() {
    local message="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# Hilfsfunktion zum sicheren Senden von Hex-Bytes
send_bytes() {
    local tmp_file=$(mktemp)
    
    # Debug-Ausgabe in Logdatei
    echo -n "Sende: " >> "$LOG_FILE"
    for byte in "$@"; do
        # Sicherstellen, dass der Wert eine Zahl ist (keine Hex-Strings wie 0xNN)
        if [[ $byte =~ ^0x ]]; then
            byte=$((byte))
        fi
        printf "%02X " $byte >> "$LOG_FILE"
        printf "\\$(printf '%03o' $byte)" >> "$tmp_file"
    done
    echo "" >> "$LOG_FILE"
    
    # Mit dd senden
    dd if="$tmp_file" of="$DEVICE" bs=1 count=$# 2>/dev/null
    rm -f "$tmp_file"
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

# Funktion zur Initialisierung der CSV-Datei
initialize_csv() {
    if [[ ! -f "$CSV_FILE" ]]; then
        echo "Zeitstempel,KWH_Total,KWH_Tarif1,KWH_Tarif2,Aktuelle_Leistung_W,Spannung_V,Strom_A" > "$CSV_FILE"
        log_message "CSV-Datei initialisiert: $CSV_FILE"
    fi
}

# Funktion zur Initialisierung der seriellen Schnittstelle
initialize_serial() {
    # Prüfe, ob das Gerät existiert
    if [[ ! -e "$DEVICE" ]]; then
        log_message "FEHLER: Gerät $DEVICE existiert nicht!"
        exit 1
    fi
    
    # Konfiguriere serielle Schnittstelle
    stty -F $DEVICE $SERIAL_CONFIG
    log_message "Serielle Schnittstelle konfiguriert: $SERIAL_CONFIG"
    
    # Puffer leeren
    dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
}

# Funktion zur Kommunikation mit dem Smart Meter
communicate_with_meter() {
    local attempt=1
    local max_attempts=3
    
    while (( attempt <= max_attempts )); do
        log_message "Kommunikationsversuch $attempt/$max_attempts..."
        
        # 1. Sende Wake-up Sequenz
        log_message "Sende Wake-up Sequenz..."
        send_bytes 0x55 0x55 0x55 0x55 0x55
        sleep 1
        
        # 2. Sende Ident-Request
        log_message "Sende Ident-Request..."
        send_bytes $START_BYTE $IDENTITY_BYTE 0x00 0x00 0x01 0x00 $REQUEST_IDENT
        sleep 1
        
        # 3. Empfange Antwort
        local response_file=$(mktemp)
        dd if="$DEVICE" of="$response_file" bs=1 count=20 iflag=nonblock 2>/dev/null
        
        # Debug: Antwort anzeigen
        if [[ -s "$response_file" ]]; then
            log_message "Antwort auf Ident-Request erhalten:"
            hexdump -C "$response_file" >> "$LOG_FILE"
            
            # Prüfe auf ACK
            if grep -q -a $'\x06' "$response_file"; then
                log_message "ACK empfangen, fahre fort"
                rm -f "$response_file"
                
                # 4. Authentifizierung, falls erforderlich
                if [[ -n "$PASSWORD" && "$PASSWORD" != "00000000" ]]; then
                    authenticate_with_meter
                fi
                
                # 5. Lese Zählerstände
                read_meter_values
                return 0
            else
                log_message "Kein ACK in der Antwort gefunden"
                hexdump -C "$response_file" >> "$LOG_FILE"
            fi
        else
            log_message "Keine Antwort erhalten"
        fi
        
        rm -f "$response_file"
        (( attempt++ ))
        sleep 2
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
read_meter_values() {
    log_message "Lese Zählerstände aus..."
    
    # Verschiedene Tabellen, die typische Zählerstände enthalten
    local tables=(
        "0001"  # Allgemeine Geräteidentifikation
        "0003"  # Status des Geräts
        "0021"  # Aktuelle Zählerregisterwerte
        "0023"  # Momentanwerte (Spannung, Strom, Leistung)
    )
    
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local kwh_total=""
    local kwh_t1=""
    local kwh_t2=""
    local power=""
    local voltage=""
    local current=""
    local data_collected=false
    
    for table in "${tables[@]}"; do
        log_message "Versuche Zugriff auf Tabelle $table..."
        
        # Konvertiere die Tabellen-ID in Bytes
        local table_high=$((0x${table:0:2}))
        local table_low=$((0x${table:2:2}))
        
        # Sende Full Read Request für die Tabelle
        send_bytes $START_BYTE $IDENTITY_BYTE 0x00 0x00 0x03 0x00 $REQUEST_READ $table_low $table_high
        sleep 1
        
        # Empfange Antwort
        local data_file=$(mktemp)
        dd if="$DEVICE" of="$data_file" bs=1 count=256 iflag=nonblock timeout=5 2>/dev/null
        
        if [[ -s "$data_file" ]]; then
            log_message "Daten für Tabelle $table empfangen"
            hexdump -C "$data_file" >> "$LOG_FILE"
            
            # Extrahiere Werte basierend auf der Tabelle
            case "$table" in
                "0001")
                    # Geräteidentifikation extrahieren und loggen
                    log_message "Geräteidentifikation gelesen"
                    data_collected=true
                    ;;
                "0003")
                    # Gerätestatus extrahieren und loggen
                    log_message "Gerätestatus gelesen"
                    data_collected=true
                    ;;
                "0021")
                    # Versuche, kWh-Werte zu extrahieren (ANSI C12.19 Struktur)
                    # Dies ist vereinfacht und muss je nach tatsächlichem Datenformat angepasst werden
                    log_message "Zählerstände gelesen"
                    
                    # Hier: Sehr vereinfachte Extraktion der Daten
                    # In echten Daten müssten die genauen Offsets und Formate bekannt sein
                    if grep -q -a "kWh" "$data_file" || grep -q -a -i "energy" "$data_file"; then
                        # Dummy-Werte, bis das tatsächliche Format bekannt ist
                        kwh_total="$(hexdump -e '"%d"' -s 20 -n 4 "$data_file" 2>/dev/null || echo "N/A")"
                        kwh_t1="$(hexdump -e '"%d"' -s 24 -n 4 "$data_file" 2>/dev/null || echo "N/A")"
                        kwh_t2="$(hexdump -e '"%d"' -s 28 -n 4 "$data_file" 2>/dev/null || echo "N/A")"
                        data_collected=true
                    fi
                    ;;
                "0023")
                    # Versuche, momentane Werte zu extrahieren
                    log_message "Momentanwerte gelesen"
                    
                    # Auch hier: Vereinfachte Extraktion
                    power="$(hexdump -e '"%d"' -s 16 -n 2 "$data_file" 2>/dev/null || echo "N/A")"
                    voltage="$(hexdump -e '"%d"' -s 18 -n 2 "$data_file" 2>/dev/null || echo "N/A")"
                    current="$(hexdump -e '"%d"' -s 20 -n 2 "$data_file" 2>/dev/null || echo "N/A")"
                    data_collected=true
                    ;;
            esac
        else
            log_message "Keine Daten für Tabelle $table empfangen"
        fi
        
        rm -f "$data_file"
        sleep 1
    done
    
    # Wenn Daten gesammelt wurden, füge sie der CSV-Datei hinzu
    if $data_collected; then
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

# Hauptfunktion
main() {
    log_message "Smart Meter Logger gestartet"
    log_message "Gerät: $DEVICE, Intervall: $POLL_INTERVAL Sekunden"
    
    # Initialisierung
    initialize_csv
    initialize_serial
    
    # Fortlaufender Betrieb starten
    log_message "Beginne mit regelmäßiger Datenabfrage..."
    
    # Fangen von Ctrl+C/SIGINT, um ordnungsgemäß zu beenden
    trap 'log_message "Skript wird beendet..."; logoff_meter; exit 0' SIGINT
    
    while true; do
        # Kommunikation mit dem Zähler
        if communicate_with_meter; then
            log_message "Erfolgreich Daten vom Zähler gelesen"
        else
            log_message "Fehler beim Lesen vom Zähler"
        fi
        
        log_message "Warte $POLL_INTERVAL Sekunden bis zur nächsten Abfrage..."
        sleep "$POLL_INTERVAL"
    done
}

# Kommandozeilenargumente verarbeiten
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Verwendung: $0 [--password PASSWORT] [--interval SEKUNDEN] [--output DATEI]"
    echo ""
    echo "Optionen:"
    echo "  --password, -p PASSWORT  Das zu verwendende Passwort (Standard: 00000000)"
    echo "  --interval, -i SEKUNDEN  Abfrageintervall in Sekunden (Standard: 60)"
    echo "  --output, -o DATEI       Name der CSV-Ausgabedatei (Standard: smart_meter_data.csv)"
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
        *)
            echo "Unbekannte Option: $1"
            echo "Verwende --help für Hilfe"
            exit 1
            ;;
    esac
done

# Skript starten
main
