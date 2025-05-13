#!/bin/bash
#
# Smart Meter Direct Scanner - Minimale Version
# Dieses Skript testet verschiedene direkte Kommandos ohne komplexen Protokoll-Handshake
# Hilfreich für die Fehlerbehebung bei Geräten, die das ANSI C12.18/19 Protokoll nicht vollständig unterstützen
#

# Konfiguration
DEVICE="${1:-/dev/ttyUSB0}"    # Entweder das erste Argument oder /dev/ttyUSB0 als Standard
LOG_FILE="direct_scan.log"
SCAN_OUTPUT="direct_scan.txt"

# Serielle Schnittstellenkonfiguration (9600 Baud, 8N1)
SERIAL_CONFIG="9600 raw cs8 -cstopb -parenb -echo -hupcl -ixoff -ixon"

# Hilfsfunktion zum Loggen von Nachrichten
log_message() {
    local message="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# Funktion zur Prüfung, ob ein Gerät existiert
check_device() {
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
        # Windows-Behandlung
        if [[ "$DEVICE" == "/dev/ttyUSB"* ]]; then
            local usb_num=${DEVICE##*/ttyUSB}
            DEVICE="COM$((usb_num + 1))"  
            log_message "Windows-Umgebung erkannt: Konvertiere zu $DEVICE"
        fi
    else
        # Linux/Unix
        if [[ ! -e "$DEVICE" ]]; then
            log_message "FEHLER: Gerät $DEVICE existiert nicht!"
            exit 1
        fi
    fi
}

# Initialisierung der seriellen Schnittstelle
initialize_serial() {
    check_device
    
    if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && "$OSTYPE" != "win32" ]]; then
        stty -F $DEVICE $SERIAL_CONFIG
        log_message "Serielle Schnittstelle konfiguriert: $SERIAL_CONFIG"
        
        # Puffer leeren
        dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
        sleep 0.5
    else
        log_message "Windows-Umgebung: Serielle Konfiguration über PowerShell"
    fi
}

# Sende eine Sequenz von Bytes
send_bytes() {
    local tmp_file=$(mktemp)
    local bytes=("$@")
    
    # Wenn keine Bytes angegeben wurden, return
    if [[ ${#bytes[@]} -eq 0 ]]; then
        rm -f "$tmp_file"
        return 1
    fi
    
    # Debug-Ausgabe in Logdatei
    echo -n "Sende: " | tee -a "$LOG_FILE"
    for byte in "${bytes[@]}"; do
        printf "%02X " $byte | tee -a "$LOG_FILE"
        printf "\\$(printf '%03o' $byte)" >> "$tmp_file"
    done
    echo "" | tee -a "$LOG_FILE"
    
    # Daten senden
    if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && "$OSTYPE" != "win32" ]]; then
        dd if="$tmp_file" of="$DEVICE" bs=1 count=${#bytes[@]} 2>/dev/null
        sync
    else
        log_message "Windows: PowerShell-Methode für serielle Kommunikation benötigt"
        # Hier müsste ein Windows-spezifischer Code sein
    fi
    
    rm -f "$tmp_file"
    sleep 0.3  # Pause nach dem Senden
}

# Sende einen String (mit Hex-Escape-Support)
send_string() {
    local raw_string="$1"
    local output_str=""
    local i=0
    local tmp_file=$(mktemp)
    
    # Debug-Info
    log_message "Sende String: $raw_string"
    
    # String mit Escape-Sequenzen direkt an die Datei
    echo -e "$raw_string" > "$tmp_file"
    
    # Ausgabe für Log
    hexdump -C "$tmp_file" >> "$LOG_FILE"
    
    # Senden
    if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && "$OSTYPE" != "win32" ]]; then
        dd if="$tmp_file" of="$DEVICE" 2>/dev/null
        sync
    else
        log_message "Windows: PowerShell-Methode für serielle Kommunikation benötigt"
    fi
    
    rm -f "$tmp_file"
    sleep 0.3
}

# Hauptfunktion für den direkten Scan
run_direct_scan() {
    # Datei mit Header erstellen
    echo "SMART METER DIRECT SCAN $(date)" > "$SCAN_OUTPUT"
    echo "===============================" >> "$SCAN_OUTPUT"
    echo "Gerät: $DEVICE" >> "$SCAN_OUTPUT"
    echo "Protokoll: Vereinfachte Kommandos ohne Handshake" >> "$SCAN_OUTPUT"
    echo "===============================" >> "$SCAN_OUTPUT"
    echo "" >> "$SCAN_OUTPUT"
    
    log_message "Starte direkten Scan mit minimalen Protokoll..."
    
    # Wake-up Sequenz
    log_message "Sende Wake-up Sequenz..."
    for i in {1..10}; do
        # 0x55 ist ein Standard-Wake-up-Byte in vielen Protokollen
        send_bytes 0x55 0x55 0x55 0x55 0x55 0x55 0x55 0x55
        sleep 0.3
    done
    sleep 1
    
    # Puffer leeren
    if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && "$OSTYPE" != "win32" ]]; then
        dd if="$DEVICE" iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
    fi
    sleep 1
    
    # Array mit verschiedenen Kommandoformaten für unterschiedliche Protokolle
    # Diese decken gängige Protokollformate für Smart Meter ab
    # IEC 62056-21, ANSI C12.18/19, Modbus-RTU, etc.
    local commands=(
        "/?!\r\n"                  # IEC 62056-21 Identification Request
        "/2\r\n"                   # Zweite IEC-Variante: Direktes Daten-Request  
        "R1\r\n"                   # Einfaches Register 1 lesen
        "R2\r\n"                   # Einfaches Register 2 lesen
        "\x01\x52\x31\x02"         # ANSI C12.18 Request mit STX/ETX Rahmen
        "\x01\x03\x00\x00\x00\x02\xC4\x0B"  # Modbus-RTU-Protokoll (Slave 1, Funktion 3, Register 0, 2 Register)
        "\xEE\x00\x00\x00\x01\x00\x20"  # SmartMeterOSGP Ident-Request (0x20)
        "\xEE\x00\x00\x00\x03\x00\x30\x00\x00"  # SmartMeterOSGP Read-Table 0
        "\xEE\x00\x00\x00\x03\x00\x30\x17\x00"  # SmartMeterOSGP Read-Table 23 (Energy)
        "\xEE\x00\x00\x00\x03\x00\x30\x1C\x00"  # SmartMeterOSGP Read-Table 28 (Power)
        "\x01\x42\x30\x03"         # DLMS/COSEM-ähnlicher Befehl
    )
    
    echo "Direkte Kommando-Tests:" >> "$SCAN_OUTPUT"
    
    # Jeden Befehl testen
    for cmd in "${commands[@]}"; do
        log_message "Teste Kommando: $cmd"
        echo -e "Kommando: $cmd" >> "$SCAN_OUTPUT"
        
        # Kommando senden
        send_string "$cmd"
        
        # Auf Antwort warten
        sleep 2
        local resp_file=$(mktemp)
        
        # Mehr Daten lesen für komplette Antworten
        if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && "$OSTYPE" != "win32" ]]; then
            dd if="$DEVICE" of="$resp_file" bs=1 count=1024 iflag=nonblock 2>/dev/null
        else
            log_message "Windows: PowerShell-Methode zum Lesen benötigt"
            # Hier müsste ein Windows-spezifischer Code sein
        fi
        
        # Antwort analysieren
        if [[ -s "$resp_file" ]]; then
            log_message "Antwort erhalten:"
            hexdump -C "$resp_file" | tee -a "$LOG_FILE"
            
            echo "Antwort erhalten:" >> "$SCAN_OUTPUT"
            hexdump -C "$resp_file" >> "$SCAN_OUTPUT"
            
            # Versuche Textinhalt anzuzeigen für IEC-ähnliche Protokolle
            if grep -q -a -E '[[:print:]]' "$resp_file"; then
                echo "Textinhalt:" >> "$SCAN_OUTPUT"
                cat "$resp_file" | grep -a -E '[[:print:]]' | sed 's/[^[:print:]]/./g' >> "$SCAN_OUTPUT"
            fi
        else
            log_message "Keine Antwort erhalten"
            echo "Keine Antwort" >> "$SCAN_OUTPUT"
        fi
        
        echo "" >> "$SCAN_OUTPUT"
        echo "-----------------------------------" >> "$SCAN_OUTPUT"
        echo "" >> "$SCAN_OUTPUT"
        
        # Puffer leeren vor dem nächsten Kommando
        if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && "$OSTYPE" != "win32" ]]; then
            dd if="$DEVICE" iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
        fi
        
        rm -f "$resp_file"
        sleep 2  # Längere Pause zwischen Kommandos
    done
    
    # Zusammenfassung
    echo "" >> "$SCAN_OUTPUT"
    echo "===============================" >> "$SCAN_OUTPUT"
    echo "Scan abgeschlossen: $(date)" >> "$SCAN_OUTPUT"
    echo "Getestete Kommandos: ${#commands[@]}" >> "$SCAN_OUTPUT"
    
    log_message "Direkter Scan abgeschlossen. Ergebnisse in $SCAN_OUTPUT gespeichert."
}

# Hauptausführung
log_message "Smart Meter Direct Scanner gestartet"
log_message "Gerät: $DEVICE"

initialize_serial
run_direct_scan

echo ""
echo "SCAN-ERGEBNISSE: $SCAN_OUTPUT"
echo ""

exit 0

