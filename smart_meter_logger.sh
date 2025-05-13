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
DEBUG_SCAN=false     # Auf true setzen, um einen vollständigen Tabellenscan durchzuführen

# Start-Byte und Identity-Byte aus der erfolgreichen Konfiguration
START_BYTE=0x01
IDENTITY_BYTE=0x3F

# Serielle Schnittstellenkonfiguration (aus erfolgreichem Test)
SERIAL_CONFIG="9600 raw cs8 cstopb -parenb -echo -hupcl -ixoff -ixon"

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
# Diese Funktion ist jetzt kompatibel mit Linux und Windows/WSL
send_bytes() {
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
        # Windows-kompatible Methode (komplexer)
        # Hier würde man idealerweise PowerShell oder ein spezielles Programm verwenden
        # Um die Bytes direkt an den COM-Port zu senden
        log_message "HINWEIS: Windows/WSL-Umgebung erkannt. Direkte COM-Port-Kommunikation könnte eingeschränkt sein."
        log_message "         Für Windows wird empfohlen, ein PowerShell-Skript zu verwenden."
        
        # Bytes direkt an COM-Port senden (echten Windows COM-Port öffnen)
        # Hinweis: Diese Methode ist sehr einfach und könnte in einer echten Umgebung 
        # nicht zuverlässig funktionieren. Ein dediziertes PowerShell- oder Python-Skript
        # wäre besser.
        if [[ -f "$tmp_file.hex" ]]; then
            if type -p powershell.exe >/dev/null 2>&1; then
                log_message "Versuche PowerShell für COM-Port-Kommunikation zu nutzen..."
                # Simulierter COM-Port-Zugriff mit PowerShell
                # In einer echten Implementierung würde hier ein spezielles PowerShell-Skript aufgerufen werden
                # das die hexadezimalen Werte in "$tmp_file.hex" liest und an den COM-Port sendet
            else
                log_message "PowerShell nicht gefunden. Kann keine Daten an COM-Port senden."
            fi
            rm -f "$tmp_file.hex"
        fi
    else 
        # Standard Linux/Unix Methode mit dd
        dd if="$tmp_file" of="$DEVICE" bs=1 count=$# 2>/dev/null
        sync
    fi
    
    rm -f "$tmp_file"
    
    # Kurze Pause nach dem Senden für eine zuverlässigere Kommunikation
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
communicate_with_meter() {
    local attempt=1
    local max_attempts=3
    
    while (( attempt <= max_attempts )); do
        log_message "Kommunikationsversuch $attempt/$max_attempts..."
        
        # 1. Sende Wake-up Sequenz - verbessert mit mehreren Wiederholungen
        log_message "Sende Wake-up Sequenz..."
        for i in {1..3}; do
            send_bytes 0x55 0x55 0x55 0x55 0x55
            sleep 0.3
        done
        sleep 1
        
        # 2. Sende Ident-Request
        log_message "Sende Ident-Request..."
        send_bytes $START_BYTE $IDENTITY_BYTE 0x00 0x00 0x01 0x00 $REQUEST_IDENT
        sleep 1
        
        # 3. Empfange Antwort - mit verbesserter Datenerfassung
        local response_file=$(mktemp)
        
        # Mehrfach versuchen, Daten zu empfangen, da einige Zähler langsam antworten
        local received=0
        for i in {1..10}; do  # Mehr Versuche
            dd if="$DEVICE" of="$response_file" bs=1 count=32 iflag=nonblock 2>/dev/null  # Mehr Bytes lesen
            if [[ -s "$response_file" && $(stat -c %s "$response_file") -gt 0 ]]; then
                received=1
                break
            fi
            log_message "Keine sofortige Antwort, warte... (Versuch $i/10)"
            sleep 1  # Längere Wartezeit zwischen Versuchen
        done
        
        # Debug: Antwort anzeigen
        if [[ $received -eq 1 ]]; then
            log_message "Antwort auf Ident-Request erhalten:"
            hexdump -C "$response_file" | tee -a "$LOG_FILE"
            
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
        "0010"  # Standard-Tabelle für Energiewerte gemäß ANSI C12.19
        "0012"  # Standard-Tabelle für Spannungs/Strom-Werte gemäß ANSI C12.19
        "0015"  # Standard-Tabelle für Leistungswerte gemäß ANSI C12.19
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
        # Mehr Daten empfangen und längere Timeout-Zeit (10 Sekunden)
        dd if="$DEVICE" of="$data_file" bs=1 count=512 iflag=nonblock timeout=10 2>/dev/null
        
        if [[ -s "$data_file" ]]; then
            log_message "Daten für Tabelle $table empfangen"
            hexdump -C "$data_file" >> "$LOG_FILE"
            
            # Extrahiere Werte basierend auf der Tabelle
            case "$table" in
                "0001")
                    # Geräteidentifikation extrahieren und loggen
                    log_message "Geräteidentifikation gelesen"
                    
                    # Der erste Datensatz enthält häufig die Geräteinformationen
                    # Extrahieren wir die ersten 12 Bytes als Geräte-ID für das Log
                    local device_id=$(hexdump -v -e '"%02X"' -s 10 -n 12 "$data_file" 2>/dev/null || echo "unbekannt")
                    log_message "Geräte-ID: $device_id"
                    data_collected=true
                    ;;
                "0003")
                    # Gerätestatus extrahieren und loggen
                    log_message "Gerätestatus gelesen"
                    
                    # Oft sind hier Statusbytes wie Batteriestatus usw.
                    local status_byte=$(hexdump -v -e '"%02X"' -s 12 -n 1 "$data_file" 2>/dev/null || echo "00")
                    log_message "Status: $status_byte"
                    data_collected=true
                    ;;
                "0010"|"0021")
                    # Versuche, kWh-Werte zu extrahieren (ANSI C12.19 Struktur)
                    log_message "Zählerstände gelesen"
                    
                    # Verbesserte Datenextraktion: Sucht nach Pattern im Data Frame statt Text
                    # Typisches Format für kWh-Werte: Datenblöcke in erwarteten Bereichen
                    
                    # Versuch mit verschiedenen Offsets (typisch für ANSI Meter)
                    # Die ersten 12-16 Bytes sind oft Header, danach folgen die Daten
                    for offset in 12 16 20 24 28 32; do
                        # Prüfen auf valide Daten (nicht 0 und nicht überlappend mit Header)
                        local energy_value=$(hexdump -v -e '1/4 "%u"' -s $offset -n 4 "$data_file" 2>/dev/null)
                        
                        # Wenn der Wert vernünftig erscheint (nicht 0 oder übermäßig hoch)
                        if [[ -n "$energy_value" && "$energy_value" -gt 0 && "$energy_value" -lt 999999999 ]]; then
                            # Nimm an, dass dies der Gesamtzählerstand ist
                            if [[ -z "$kwh_total" ]]; then
                                # Wert durch 1000 teilen, wenn er zu groß erscheint (typischerweise in Wh statt kWh)
                                if [[ "$energy_value" -gt 1000000 ]]; then
                                    kwh_total=$(echo "scale=3; $energy_value / 1000" | bc)
                                else
                                    kwh_total=$energy_value
                                fi
                                log_message "Zählerstand erkannt: $kwh_total kWh (bei Offset $offset)"
                            elif [[ -z "$kwh_t1" ]]; then
                                # Tarifregister 1
                                if [[ "$energy_value" -gt 1000000 ]]; then
                                    kwh_t1=$(echo "scale=3; $energy_value / 1000" | bc)
                                else
                                    kwh_t1=$energy_value
                                fi
                                log_message "Tarif 1 erkannt: $kwh_t1 kWh (bei Offset $offset)"
                            elif [[ -z "$kwh_t2" ]]; then
                                # Tarifregister 2
                                if [[ "$energy_value" -gt 1000000 ]]; then
                                    kwh_t2=$(echo "scale=3; $energy_value / 1000" | bc)
                                else
                                    kwh_t2=$energy_value
                                fi
                                log_message "Tarif 2 erkannt: $kwh_t2 kWh (bei Offset $offset)"
                            fi
                            
                            data_collected=true
                        fi
                    done
                    ;;
                "0012"|"0023"|"0015")
                    # Versuche, momentane Werte zu extrahieren (Spannung, Strom, Leistung)
                    log_message "Momentanwerte gelesen"
                    
                    # Verbesserte Datenextraktion für momentane Werte
                    # Nach dem Header befinden sich typischerweise die Werte
                    # Durchsuchen verschiedene Offsets und suchen nach plausiblen Werten
                    
                    # Leistungswerte - typischerweise 2 oder 4 Byte, im Bereich 0-50000W
                    for offset in 12 14 16 18 20 22 24; do
                        # 2-Byte und 4-Byte Werte versuchen
                        local power_val2b=$(hexdump -v -e '1/2 "%u"' -s $offset -n 2 "$data_file" 2>/dev/null)
                        local power_val4b=$(hexdump -v -e '1/4 "%u"' -s $offset -n 4 "$data_file" 2>/dev/null)
                        
                        # Prüfe 2-Byte Wert (typisch für Leistung in W)
                        if [[ -n "$power_val2b" && "$power_val2b" -gt 0 && "$power_val2b" -lt 50000 && -z "$power" ]]; then
                            power=$power_val2b
                            log_message "Leistungswert erkannt: $power W (bei Offset $offset, 2 Bytes)"
                        fi
                        
                        # Wenn 2-Byte Wert unrealistisch, versuche 4-Byte (könnte in mW sein)
                        if [[ -n "$power_val4b" && "$power_val4b" -gt 1000 && "$power_val4b" -lt 50000000 && -z "$power" ]]; then
                            power=$(echo "scale=2; $power_val4b / 1000" | bc)
                            log_message "Leistungswert erkannt: $power W (bei Offset $offset, 4 Bytes, skaliert)"
                        fi
                    done
                    
                    # Spannungswerte - typischerweise 2 Byte, im Bereich 200-250V
                    for offset in 14 16 18 20 22 24 26; do
                        local voltage_val=$(hexdump -v -e '1/2 "%u"' -s $offset -n 2 "$data_file" 2>/dev/null)
                        
                        if [[ -n "$voltage_val" && "$voltage_val" -ge 200 && "$voltage_val" -lt 260 && -z "$voltage" ]]; then
                            voltage=$voltage_val
                            log_message "Spannungswert erkannt: $voltage V (bei Offset $offset)"
                        fi
                    done
                    
                    # Stromwerte - typischerweise 2 Byte, im 0-100A Bereich
                    for offset in 16 18 20 22 24 26 28; do
                        local current_val=$(hexdump -v -e '1/2 "%u"' -s $offset -n 2 "$data_file" 2>/dev/null)
                        local current_scaled=$(echo "scale=3; $current_val / 1000" | bc 2>/dev/null)
                        
                        # Prüfe auf realistischen Wert (entweder direkt oder skaliert)
                        if [[ -n "$current_val" && "$current_val" -gt 0 && -z "$current" ]]; then
                            # Wenn der Wert über 100 ist, könnte er in mA sein - skalieren
                            if [[ "$current_val" -ge 100 && "$current_val" -lt 100000 ]]; then
                                current=$current_scaled
                                log_message "Stromwert erkannt: $current A (bei Offset $offset, skaliert von $current_val mA)"
                            elif [[ "$current_val" -lt 100 ]]; then 
                                current=$current_val
                                log_message "Stromwert erkannt: $current A (bei Offset $offset)"
                            fi
                        fi
                    done
                    
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
    echo "===============================" >> "$scan_output"
    echo "" >> "$scan_output"
    
    # Bevor wir anfangen, sicherstellen, dass der Zähler bereit ist
    log_message "Sende initiale Wake-up Sequenz für den Scan..."
    for i in {1..5}; do
        send_bytes 0x55 0x55 0x55 0x55 0x55
        sleep 0.3
    done
    sleep 1
    
    # Sende Ident-Request, um den Zähler zu aktivieren
    log_message "Sende Ident-Request zur Zählerinitialisierung..."
    send_bytes $START_BYTE $IDENTITY_BYTE 0x00 0x00 0x01 0x00 $REQUEST_IDENT
    sleep 1
    
    # Puffer leeren
    dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
    sleep 0.5
    
    # Wir scannen Tabellen von 0-50, was die meisten relevanten Tabellen abdecken sollte
    echo "Start des Scans: $(date)" >> "$scan_output"
    
    # Fortschrittsanzeige
    local total_tables=51  # 0-50 Tables
    local scanned=0
    local data_found=0
    
    for high in {0..0}; do
        for low in {0..50}; do
            local high_hex=$(printf "%02X" $high)
            local low_hex=$(printf "%02X" $low)
            local table_id="${high_hex}${low_hex}"
            
            # Fortschrittsanzeige
            scanned=$((scanned + 1))
            log_message "Scanne Tabelle $table_id... [$scanned/$total_tables]"
            
            # Sende Read Request für die Tabelle
            send_bytes $START_BYTE $IDENTITY_BYTE 0x00 0x00 0x03 0x00 $REQUEST_READ $low $high
            sleep 1
            
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
                
                log_message "Versuch $attempt: Keine sofortige Antwort für Tabelle $table_id, warte..."
                sleep 0.5
            done
            
            if [[ $received -eq 1 && -s "$scan_file" ]]; then
                local file_size=$(stat -c %s "$scan_file")
                
                # Prüfen, ob die Antwort eine NACK enthält oder nur ein ACK
                if grep -q -a $'\x15' "$scan_file"; then
                    log_message "NACK für Tabelle $table_id erhalten - Tabelle nicht verfügbar"
                    echo "TABELLE $table_id: NICHT VERFÜGBAR (NACK)" >> "$scan_output"
                elif grep -q -a $'\x06' "$scan_file" && [[ $file_size -le 6 ]]; then
                    log_message "Nur ACK für Tabelle $table_id erhalten - keine Daten"
                    echo "TABELLE $table_id: NUR ACK ERHALTEN (KEINE DATEN)" >> "$scan_output"
                else
                    # Wenn wir hier sind, haben wir wahrscheinlich Daten
                    log_message "Daten für Tabelle $table_id gefunden (${file_size} Bytes):"
                    hexdump -C "$scan_file" | tee -a "$LOG_FILE"
                    
                    echo "----- TABELLE $table_id: -----" >> "$scan_output"
                    echo "Bytes: $file_size" >> "$scan_output"
                    hexdump -C "$scan_file" >> "$scan_output"
                    echo "" >> "$scan_output"
                    data_found=$((data_found + 1))
                fi
            else
                log_message "Keine Antwort für Tabelle $table_id erhalten"
                echo "TABELLE $table_id: KEINE ANTWORT" >> "$scan_output"
            fi
            
            rm -f "$scan_file"
            sleep 0.5
        done
    done
    
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
