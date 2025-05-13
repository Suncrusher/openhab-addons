#!/bin/bash
#
# Hinweise zur Verwendung:
#
# 1. Grundlegende Verwendung:
#     ./smart_meter_reader.sh
# 2. Mit angepassten Parametern:
#     ./smart_meter_reader.sh --device /dev/ttyUSB0 --password "Ihr_Passwort" --interval 30
# 3. Hilfe anzeigen:
#     ./smart_meter_reader.sh --help


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
DEBUG=1              # Debug-Modus (0=aus, 1=an)
MAX_RETRY=3          # Maximale Anzahl von Wiederholungsversuchen bei Kommunikationsfehlern

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
    
    # Paket in ein temporäres File schreiben und direkt mit dd senden
    local tmp_file=$(mktemp)
    
    # Debug-Ausgabe in Hex-Format
    echo -n "Sending: " >&2
    for byte in "${packet[@]}"; do
        # Sicherstellen, dass der Wert eine Zahl ist (keine Hex-Strings wie 0xNN)
        if [[ $byte =~ ^0x ]]; then
            byte=$((byte))
        fi
        printf "%02X " $byte >&2
        printf "\\$(printf '%03o' $byte)" >> "$tmp_file"
    done
    echo "" >&2
    
    # Direkt mit dd senden, um Probleme mit NULL-Bytes zu vermeiden
    dd if="$tmp_file" of="$DEVICE" bs=1 count=${#packet[@]} 2>/dev/null
    rm -f "$tmp_file"
    
    # Auf ACK warten - verwende dd, um jegliche Byte-Probleme zu vermeiden
    local tmp_response=$(mktemp)
    
    # Timeout implementieren
    local start_time=$(date +%s)
    local timeout=5  # Längerer Timeout
    local retries=3  # Anzahl der Wiederholungsversuche
    local retry_count=0
    
    # Mehrere Versuche bei fehlender oder falscher Antwort
    while (( retry_count < retries )); do
        echo "Warte auf ACK (Versuch $((retry_count+1))/$retries)..." >&2
        
        # Mehrere Bytes lesen, um Antworten zu finden
        dd if="$DEVICE" of="$tmp_response" bs=1 count=10 iflag=nonblock 2>/dev/null
        
        if [[ -s "$tmp_response" ]]; then
            # Hexdump für bessere Diagnose
            echo "Empfangene Antwort:" >&2
            hexdump -C "$tmp_response" >&2
            
            # Prüfe jedes Byte auf ACK oder NACK
            local found_ack=false
            local found_nack=false
            local nack_position=-1
            
            # Lese einzeln und prüfe auf ACK oder NACK
            for i in {0..9}; do
                local byte_hex=$(dd if="$tmp_response" bs=1 skip=$i count=1 2>/dev/null | xxd -p)
                if [[ -n "$byte_hex" ]]; then
                    local byte_dec=$((0x$byte_hex))
                    
                    if [[ "$byte_dec" == "6" ]]; then  # ACK = 0x06
                        echo "ACK (0x06) gefunden an Position $i" >&2
                        found_ack=true
                        break
                    elif [[ "$byte_dec" == "21" ]]; then  # NACK = 0x15 (21 dezimal)
                        echo "NACK (0x15) gefunden an Position $i" >&2
                        found_nack=true
                        nack_position=$i
                        # Bei NACK nicht sofort abbrechen - eventuell kommt noch ein ACK
                    fi
                fi
            done
            
            if $found_ack; then
                echo "ACK empfangen" >&2
                rm -f "$tmp_response"
                return 0
            elif $found_nack; then
                echo "NACK empfangen - Protokollfehler oder falsche Baudrate?" >&2
                echo "Analyse des NACK-Kontexts:" >&2
                
                # Zeige Bytes vor und nach NACK für bessere Diagnose
                if [[ $nack_position -gt 0 ]]; then
                    local pre_nack=$(dd if="$tmp_response" bs=1 count=$nack_position 2>/dev/null | xxd -p)
                    echo "Bytes vor NACK: $pre_nack" >&2
                fi
                
                if [[ $nack_position -lt 9 ]]; then
                    local post_nack=$(dd if="$tmp_response" bs=1 skip=$((nack_position+1)) 2>/dev/null | xxd -p)
                    echo "Bytes nach NACK: $post_nack" >&2
                fi
                
                retry_count=$((retry_count + 1))
            else
                echo "Kein ACK/NACK in der Antwort gefunden, versuche erneut..." >&2
                retry_count=$((retry_count + 1))
                
                # Leere temporäre Datei
                > "$tmp_response"
                
                if (( retry_count < retries )); then
                    sleep 0.5
                    continue
                fi
            fi
        fi
        
        echo "Keine Antwort erhalten, versuche erneut..." >&2
        retry_count=$((retry_count + 1))
        
        if (( retry_count < retries )); then
            sleep 0.5
        fi
    done
    
    echo "Keine ACK-Antwort nach $retries Versuchen" >&2
    rm -f "$tmp_response"
    return 1
}

# Adaptives Start-Byte Erkennen in receive_message
function receive_message {
    # Wir verwenden temporäre Dateien, um binäre Daten korrekt zu verarbeiten
    local header_file=$(mktemp)
    local body_file=$(mktemp)
    local full_msg_file=$(mktemp)
    
    # Timeout für die Antwort
    local timeout=10
    local start_time=$(date +%s)
    local found_start=0
    local start_byte_hex=""

    # Umwandlung des START_BYTE in Hex für Vergleiche
    if [[ "$START_BYTE" =~ ^0x ]]; then
        start_byte_hex=$(printf "%02x" $START_BYTE)
    else
        start_byte_hex=$(printf "%02x" $(($START_BYTE)))
    fi
    
    echo "Warte auf Start-Byte (0x${start_byte_hex^^})..." >&2
    
    # Warten auf Start-Byte mit adaptiver Erkennung
    while (( $(date +%s) - start_time < timeout )); do
        # Lese ein einzelnes Byte
        dd if=$DEVICE of=$header_file bs=1 count=1 iflag=nonblock 2>/dev/null
        
        if [[ -s "$header_file" ]]; then
            local byte_hex=$(xxd -p "$header_file")
            
            # Prüfen ob das empfangene Byte dem erwarteten Start-Byte entspricht
            if [[ "$byte_hex" == "$start_byte_hex" ]]; then
                echo "Start-Byte (0x${start_byte_hex^^}) gefunden" >&2
                found_start=1
                cat $header_file > $full_msg_file
                break
            # Alternativ prüfen wir auf andere mögliche Start-Bytes 
            elif [[ "$byte_hex" == "ee" && "$start_byte_hex" != "ee" ]]; then
                echo "Alternatives Start-Byte 0xEE gefunden statt 0x${start_byte_hex^^}, akzeptiere..." >&2
                found_start=1
                cat $header_file > $full_msg_file
                break
            elif [[ "$byte_hex" == "ff" && "$start_byte_hex" != "ff" ]]; then
                echo "Alternatives Start-Byte 0xFF gefunden statt 0x${start_byte_hex^^}, akzeptiere..." >&2
                found_start=1
                cat $header_file > $full_msg_file
                break
            elif [[ "$byte_hex" == "01" && "$start_byte_hex" != "01" ]]; then
                echo "Alternatives Start-Byte 0x01 gefunden statt 0x${start_byte_hex^^}, akzeptiere..." >&2
                found_start=1
                cat $header_file > $full_msg_file
                break
            else
                echo "Unerwartetes Byte: 0x${byte_hex^^}, warte weiter..." >&2
                > $header_file  # Datei leeren für nächsten Versuch
            fi
        fi
        
        sleep 0.1
    done

    if [[ $found_start -eq 0 ]]; then
        echo "Timeout bei Empfang des Start-Bytes" >&2
        rm -f "$header_file" "$body_file" "$full_msg_file"
        return 1
    fi
    
    # Lese Identity, Control, und Länge (4 Bytes)
    dd if=$DEVICE of=$header_file bs=1 count=4 2>/dev/null || { 
        echo "Fehler beim Lesen des Headers" >&2
        rm -f "$header_file" "$body_file" "$full_msg_file"
        return 1
    }
    
    # Header zum vollständigen Nachrichten-File hinzufügen
    cat $header_file >> $full_msg_file
    
    # Header analysieren
    local control=$(hexdump -s 2 -n 1 -e '"%d"' $header_file)
    local length_bytes=$(dd if=$header_file bs=1 skip=3 count=2 2>/dev/null | xxd -p)
    
    # Länge berechnen (Little Endian)
    if [[ ${#length_bytes} -eq 4 ]]; then
        length_byte1=$((0x${length_bytes:0:2}))
        length_byte2=$((0x${length_bytes:2:2}))
        length=$((length_byte1 + length_byte2 * 256))
    else
        echo "Fehler bei der Längenberechnung: $length_bytes" >&2
        length=0
    fi
    
    echo "Control: $control, Payload-Länge: $length Bytes" >&2
    
    # Lese Daten gemäß der Länge plus CRC (2 Bytes)
    dd if=$DEVICE of=$body_file bs=1 count=$((length+2)) 2>/dev/null
    
    # Zum vollständigen Nachrichten-File hinzufügen
    cat $body_file >> $full_msg_file
    
    echo "Nachricht empfangen, sende ACK..." >&2
    
    # Sende ACK zurück mit dd
    printf '\x06' | dd of=$DEVICE 2>/dev/null
    
    # Debug: Vollständige Nachricht
    echo "Empfangene Nachricht:" >&2
    hexdump -C $full_msg_file >&2
    
    # Base64-kodierte Daten zurückgeben (sicherer für Binärdaten)
    base64 $full_msg_file
    
    # Temporäre Dateien löschen
    rm -f "$header_file" "$body_file" "$full_msg_file"
}

# Funktion zum Parsen der Tabellenantwort
function parse_table_data {
    local base64_data="$1"
    local table="$2"
    
    # Dekodiere Base64-Daten in eine temporäre Binärdatei
    local tmp_file=$(mktemp)
    echo "$base64_data" | base64 -d > "$tmp_file"
    
    # Debug
    echo "Empfangene Daten (dekodiert):" >&2
    hexdump -C "$tmp_file" >&2
    
    # Hier müssen die Bytes ab Position 6 (nach Header) geparst werden
    # Byte 6: Response Code
    # Byte 7: Table ID
    # Ab Byte 8: Tabellendaten
    
    # Achten Sie auf die Byte-Reihenfolge (jetzt binary safe durch temporäre Dateien)
    if [[ "$table" == "23" ]]; then
        # Tabelle 23: Vorwärts- und rückwärts aktive Energie
        # Position 8 startet nach Header (6) + Response Code (1) + Table ID (1)
        
        # Die Daten sollten Big-Endian sein, daher little-endian in hexdump
        # format string spezifizieren: '%d' für decimal-Output, Gruppierung in 4-Byte-Blöcke
        fwd_energy=$(hexdump -s 8 -n 4 -e '1 "">>"" 4/1 "%u"' "$tmp_file" 2>/dev/null || echo 0)
        rev_energy=$(hexdump -s 12 -n 4 -e '1 "">>"" 4/1 "%u"' "$tmp_file" 2>/dev/null || echo 0)
        
        echo "Rohe Zählerwerte: FWD=$fwd_energy REV=$rev_energy" >&2
        
        fwd_energy_kwh=$(echo "scale=3; $fwd_energy/1000.0" | bc)
        rev_energy_kwh=$(echo "scale=3; $rev_energy/1000.0" | bc)
        
        echo "Vorwärts aktive Energie: $fwd_energy_kwh kWh, Rückwärts aktive Energie: $rev_energy_kwh kWh" >&2
        echo "$fwd_energy_kwh,$rev_energy_kwh,,,,,,,,"
        
    elif [[ "$table" == "28" ]]; then
        # Tabelle 28: Aktuelle Leistungs- und Spannungswerte
        # Für jedes 4-Byte-Wort nutzen wir separate hexdump-Aufrufe für mehr Kontrolle
        fwd_power=$(hexdump -s 8 -n 4 -e '1 "">>"" 4/1 "%u"' "$tmp_file" 2>/dev/null || echo 0)
        rev_power=$(hexdump -s 12 -n 4 -e '1 "">>"" 4/1 "%u"' "$tmp_file" 2>/dev/null || echo 0)
        import_reactive=$(hexdump -s 16 -n 4 -e '1 "">>"" 4/1 "%u"' "$tmp_file" 2>/dev/null || echo 0)
        export_reactive=$(hexdump -s 20 -n 4 -e '1 "">>"" 4/1 "%u"' "$tmp_file" 2>/dev/null || echo 0)
        l1_current=$(hexdump -s 24 -n 4 -e '1 "">>"" 4/1 "%u"' "$tmp_file" 2>/dev/null || echo 0)
        l2_current=$(hexdump -s 28 -n 4 -e '1 "">>"" 4/1 "%u"' "$tmp_file" 2>/dev/null || echo 0)
        l3_current=$(hexdump -s 32 -n 4 -e '1 "">>"" 4/1 "%u"' "$tmp_file" 2>/dev/null || echo 0)
        l1_voltage=$(hexdump -s 36 -n 4 -e '1 "">>"" 4/1 "%u"' "$tmp_file" 2>/dev/null || echo 0)
        l2_voltage=$(hexdump -s 40 -n 4 -e '1 "">>"" 4/1 "%u"' "$tmp_file" 2>/dev/null || echo 0)
        l3_voltage=$(hexdump -s 44 -n 4 -e '1 "">>"" 4/1 "%u"' "$tmp_file" 2>/dev/null || echo 0)
        
        echo "Rohe Leistungswerte: FWD=$fwd_power REV=$rev_power" >&2
        
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
    
    # Temporäre Datei aufräumen
    rm -f "$tmp_file"
}

# Funktion zum Initialisieren der Verbindung
function initialize_connection {
    echo "Konfiguriere serielle Schnittstelle $DEVICE..." >&2
    
    # Prüfe, ob das Gerät existiert
    if [[ ! -e "$DEVICE" ]]; then
        echo "FEHLER: Gerät $DEVICE existiert nicht!" >&2
        return 1
    fi
    
    # Prüfe, ob gespeicherte Konfiguration vorhanden ist
    if load_saved_config; then
        echo "Verwende gespeicherte Konfiguration: $SUCCESSFUL_CONFIG" >&2
        echo "Verwende gespeichertes Start-Byte: $SUCCESSFUL_START_BYTE" >&2
        
        # Setze das gespeicherte Start-Byte
        START_BYTE=$SUCCESSFUL_START_BYTE
        
        # Konfiguriere serielle Schnittstelle mit gespeicherten Einstellungen
        stty -F $DEVICE $SUCCESSFUL_CONFIG
    else
        # Keine Konfiguration gefunden, verwende Standardeinstellungen
        echo "Keine gespeicherte Konfiguration gefunden, verwende Standardeinstellungen..." >&2
        echo "Konfiguration 1: Basiskonfiguration (9600 8N1)" >&2
        stty -F $DEVICE 9600 raw cs8 -cstopb -parenb -echo
        
        # Reset RTS/DTR Signale
        if command -v stty &>/dev/null; then
            echo "Setze RTS high, DTR low" >&2
            # Versuche spezielle Signale zu setzen
            stty -F $DEVICE -hupcl
        fi
    fi
    
    # Warte einen Moment, bis die Schnittstelle bereit ist
    sleep 2
    
    # Setze Toggle-Control zurück
    TOGGLE_CONTROL=0
    
    # Flush any pending input
    dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
    
    # Sende erweiterte Wake-up Sequenz für bessere Erkennung
    echo "Sende erweiterte Wake-up Sequenz (0x55, Pausen, 0x00)..." >&2
    
    # 1. Sende mehrere 0x55 mit längeren Pausen dazwischen
    for i in {1..10}; do
        echo -ne "\x55" > $DEVICE
        sleep 0.3
    done
    
    # 2. Kurze Pause
    sleep 1.0
    
    # 3. Sende zusätzliche NULL-bytes für Synchronisierung
    for i in {1..3}; do
        echo -ne "\x00" > $DEVICE
        sleep 0.3
    done
    
    # 4. Finale Pause
    sleep 1.5
    
    # Sende IDENT-Request
    echo "Sende Ident-Request..." >&2
    if ! send_message $REQUEST_ID_IDENT; then
        echo "FEHLER: Ident-Request fehlgeschlagen" >&2
        return 1
    fi
    
    # Verzögerung zwischen den Befehlen
    sleep 0.5
    
    # Sende NEGOTIATE-Request
    echo "Sende Negotiate-Request..." >&2
    if ! send_message $REQUEST_ID_NEGOTIATE2 0x40 0x00 0x02 0x01; then
        echo "FEHLER: Negotiate-Request fehlgeschlagen" >&2
        return 1
    fi
    
    # Verzögerung zwischen den Befehlen
    sleep 0.5
    
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
    
    # Verzögerung zwischen den Befehlen
    sleep 0.5
    
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

# Funktion zum Testen verschiedener serieller Konfigurationen
function test_serial_configs {
    echo "Teste verschiedene serielle Konfigurationen für $DEVICE..." >&2
    
    local configs=(
        "300 raw cs8 -cstopb -parenb -echo"    # Oft für ältere Zähler verwendet
        "1200 raw cs8 -cstopb -parenb -echo"   # Ebenfalls häufig bei Zählern
        "2400 raw cs8 -cstopb -parenb -echo"   # Mittlere Geschwindigkeit
        "4800 raw cs8 -cstopb -parenb -echo"   # Häufig bei neueren Zählern
        "9600 raw cs8 -cstopb -parenb -echo"   # Standard
        "9600 raw cs8 -cstopb -parenb -crtscts -echo"
        "9600 raw cs8 cstopb -parenb -echo"
        "9600 raw cs8 -cstopb parenb -echo"
        "9600 raw cs8 -cstopb parenb parodd -echo"
        "19200 raw cs8 -cstopb -parenb -echo"
    )
    
    local rts_dtr_settings=(
        "-hupcl"        # RTS=high, DTR=low
        "hupcl"         # RTS=low, DTR=high
        ""              # Standard-Einstellungen
    )
    
    for config in "${configs[@]}"; do
        for rts_dtr in "${rts_dtr_settings[@]}"; do
            echo "Versuche Konfiguration: $config $rts_dtr" >&2
            
            # Serielle Schnittstelle konfigurieren
            stty -F $DEVICE $config
            
            if [[ -n "$rts_dtr" ]]; then
                stty -F $DEVICE $rts_dtr
            fi
            
            # Setze Toggle-Control zurück
            TOGGLE_CONTROL=0
            
            # Flush any pending input
            dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
            
            # Warte einen Moment
            sleep 1
            
            # Sende Wake-up Signal
            echo -ne "\x55" > $DEVICE
            sleep 0.5
            
            # Teste verschiedene mögliche Start-Bytes für das Protokoll
            local start_bytes=(0xEE 0xFF 0x01 0xFE)
            
            for test_start_byte in "${start_bytes[@]}"; do
                echo "Teste Start-Byte $test_start_byte mit Konfiguration $config $rts_dtr" >&2
                
                # Temporär das Start-Byte ändern
                local original_start=$START_BYTE
                START_BYTE=$test_start_byte
                
                # Versuche Ident-Request
                echo "Sende Test Ident-Request..." >&2
                if send_message $REQUEST_ID_IDENT; then
                    echo "ERFOLG: Konfiguration funktioniert mit Start-Byte $test_start_byte!" >&2
                    echo "Erfolgreiche Konfiguration: $config $rts_dtr, Start-Byte: $test_start_byte" >&2
                    
                    # Speichere die erfolgreiche Konfiguration
                    SUCCESSFUL_CONFIG="$config $rts_dtr"
                    SUCCESSFUL_START_BYTE=$test_start_byte
                    
                    # Speichere die Konfiguration für zukünftige Nutzung
                    save_successful_config
                    
                    # Originales Start-Byte wiederherstellen
                    START_BYTE=$original_start
                    return 0
                fi
                
                # Originales Start-Byte wiederherstellen
                START_BYTE=$original_start
            done
            
            echo "Diese Konfiguration funktioniert nicht, versuche nächste..." >&2
            sleep 2
        done
    done
    
    echo "Keine der getesteten Konfigurationen war erfolgreich." >&2
    return 1
}

# Funktion für erweiterten Protokolltest mit verschiedenen Protokollvarianten
function test_protocol_variants {
    echo "Starte erweiterten Protokolltest für verschiedene Varianten..." >&2
    
    # Protokollvarianten zum Testen
    local variants=(
        "standard"       # Standard-C12.18
        "legacy"         # Ältere Variante mit Start-Byte 0xFF
        "simple"         # Vereinfachter Handshake für ältere Geräte
        "inverted"       # Invertierte Kontroll-Bits
    )
    
    # Teste jede Variante
    for variant in "${variants[@]}"; do
        echo "Teste Protokollvariante: $variant" >&2
        
        # Serielle Schnittstelle konfigurieren (verwenden Sie die aktuellen Einstellungen)
        if [[ -n "$SUCCESSFUL_CONFIG" ]]; then
            stty -F $DEVICE $SUCCESSFUL_CONFIG
        else
            # Standard-Konfiguration für den Test
            stty -F $DEVICE 9600 raw cs8 -cstopb -parenb -echo -hupcl
        fi
        
        # Setze Toggle-Control zurück
        TOGGLE_CONTROL=0
        
        # Flush buffer
        dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
        sleep 1
        
        # Protokollspezifische Einstellungen anpassen
        case "$variant" in
            "standard")
                # Standard-Einstellungen
                START_BYTE=0xEE
                IDENTITY_BYTE=0x00
                ;;
            "legacy")
                # Ältere Geräte könnten ein anderes Start-Byte verwenden
                START_BYTE=0xFF
                IDENTITY_BYTE=0x00
                ;;
            "simple")
                # Vereinfachter Handshake mit 0x01 als Start-Byte
                START_BYTE=0x01
                IDENTITY_BYTE=0x00
                # Sende spezielle Wakeup-Sequenz
                for i in {1..3}; do
                    echo -ne "\x01" > $DEVICE
                    sleep 0.5
                done
                ;;
            "inverted")
                # Einige Geräte verwenden invertierte Kontrollbits
                START_BYTE=0xEE
                IDENTITY_BYTE=0x01
                ;;
        esac
        
        echo "Variante $variant: START_BYTE=$START_BYTE, IDENTITY_BYTE=$IDENTITY_BYTE" >&2
        
        # Erweiterte Sequenz senden für bessere Erkennung
        echo "Sende Wake-up-Sequenz für $variant..." >&2
        for i in {1..5}; do
            echo -ne "\x55" > $DEVICE
            sleep 0.3
        done
        sleep 1.0
        
        # Versuche Ident-Request mit der aktuellen Variante
        echo "Sende Test Ident-Request mit Variante $variant..." >&2
        if send_message $REQUEST_ID_IDENT; then
            echo "ERFOLG: Protokollvariante $variant funktioniert!" >&2
            
            # Speichere erfolgreiche Protokollvariante
            SUCCESSFUL_VARIANT="$variant"
            save_successful_config
            
            return 0
        else
            # Versuche ein alternatives Format für den Ident-Request
            echo "Erste Anfrage fehlgeschlagen, versuche alternativen Ansatz..." >&2
            
            # Bei manchen Zählern muss man zuerst einen "Reset"-Befehl senden
            if [[ "$variant" == "legacy" || "$variant" == "simple" ]]; then
                echo "Sende Reset-Befehl für Variante $variant..." >&2
                echo -ne "\x1B" > $DEVICE # ESC-Zeichen zum Zurücksetzen
                sleep 1.0
                
                # Erneuter Versuch mit Ident-Request
                if send_message $REQUEST_ID_IDENT; then
                    echo "ERFOLG nach Reset: Protokollvariante $variant funktioniert!" >&2
                    SUCCESSFUL_VARIANT="$variant"
                    save_successful_config
                    return 0
                fi
            fi
        fi
        
        echo "Protokollvariante $variant funktioniert nicht." >&2
        sleep 2
    done
    
    echo "Keine der getesteten Protokollvarianten war erfolgreich." >&2
    return 1
}

# Globale Variablen für erfolgreiche Konfigurationen
SUCCESSFUL_CONFIG=""
SUCCESSFUL_START_BYTE=0xEE
SUCCESSFUL_VARIANT="standard"
SUCCESSFUL_IDENTITY_BYTE=0x00
CONFIG_FILE="${HOME}/.smart_meter_config"

# Funktion zum Speichern der erfolgreichen Konfiguration
function save_successful_config {
    echo "# Smart Meter OSGP Reader Konfiguration" > "$CONFIG_FILE"
    echo "SUCCESSFUL_CONFIG=\"$SUCCESSFUL_CONFIG\"" >> "$CONFIG_FILE"
    echo "SUCCESSFUL_START_BYTE=$SUCCESSFUL_START_BYTE" >> "$CONFIG_FILE"
    echo "SUCCESSFUL_VARIANT=\"$SUCCESSFUL_VARIANT\"" >> "$CONFIG_FILE"
    echo "SUCCESSFUL_IDENTITY_BYTE=$SUCCESSFUL_IDENTITY_BYTE" >> "$CONFIG_FILE"
    echo "Konfiguration gespeichert: $SUCCESSFUL_CONFIG, Start-Byte: $SUCCESSFUL_START_BYTE" >&2
    echo "Protokollvariante: $SUCCESSFUL_VARIANT, Identity-Byte: $SUCCESSFUL_IDENTITY_BYTE" >&2
}

# Funktion zum Laden der erfolgreichen Konfiguration
function load_saved_config {
    if [[ -f "$CONFIG_FILE" ]]; then
        echo "Lade gespeicherte Konfiguration..." >&2
        source "$CONFIG_FILE"
        echo "Geladene Konfiguration:" >&2
        echo "- Serielle Einstellungen: $SUCCESSFUL_CONFIG" >&2
        echo "- Start-Byte: $SUCCESSFUL_START_BYTE" >&2
        echo "- Protokollvariante: $SUCCESSFUL_VARIANT" >&2
        echo "- Identity-Byte: $SUCCESSFUL_IDENTITY_BYTE" >&2
        return 0
    fi
    echo "Keine gespeicherte Konfiguration gefunden" >&2
    return 1
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
    
    # Prüfe verschiedene serielle Konfigurationen beim ersten Start
    echo "Teste serielle Konfigurationen für beste Kommunikation..." >&2
    test_serial_configs
    
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

# Funktion zum Überprüfen der Abhängigkeiten
check_dependencies() {
    local missing=0
    for cmd in dd hexdump stty xxd base64 bc; do
        if ! command -v $cmd &>/dev/null; then
            echo "FEHLER: Benötigtes Programm '$cmd' nicht gefunden. Bitte installieren." >&2
            missing=1
        fi
    done
    
    if [[ $missing -eq 1 ]]; then
        echo "Unter Debian/Ubuntu können Sie die fehlenden Programme mit installieren:" >&2
        echo "sudo apt-get install coreutils bsdextra util-linux xxd base64 bc" >&2
        exit 1
    fi
    
    # Überprüfe Zugriff auf serielle Schnittstelle
    if [[ ! -r "$DEVICE" || ! -w "$DEVICE" ]]; then
        echo "FEHLER: Keine Lese-/Schreibrechte für $DEVICE" >&2
        echo "Führen Sie das Skript mit sudo aus oder fügen Sie Ihren Benutzer zur dialout-Gruppe hinzu:" >&2
        echo "sudo usermod -a -G dialout \$USER" >&2
        echo "Danach müssen Sie sich ab- und wieder anmelden." >&2
        exit 1
    fi
}

# Funktion zum Anzeigen der Hilfe
show_help() {
    cat <<EOH
Smart Meter OSGP Reader

Verwendung: $0 [Optionen]

Optionen:
  -d, --device DEVICE    Serielles Gerät (Standard: $DEVICE)
  -u, --user USERNAME    Benutzername (Standard: $USERNAME)
  -p, --password PWD     Passwort (Standard: $PASSWORD)
  -i, --interval SEC     Aktualisierungsintervall in Sekunden (Standard: $POLL_INTERVAL)
  -o, --output FILE      CSV-Ausgabedatei (Standard: $CSV_FILE)
  -D, --debug            Debug-Modus aktivieren (mehr Ausgaben)
  -t, --test-configs     Seriellen Port mit verschiedenen Konfigurationen testen
  -P, --test-protocol    Verschiedene Protokollvarianten testen
  -x, --diagnose         Detaillierte Protokolldiagnose durchführen
  -r, --max-retry NUM    Maximale Anzahl von Wiederholungsversuchen (Standard: $MAX_RETRY)
  -h, --help             Diese Hilfe anzeigen

Beispiele:
  $0 --device /dev/ttyUSB0 --password "12345678" --interval 30
  $0 --debug --test-configs       # Nur serielle Konfigurationen testen
  $0 --device /dev/ttyUSB1 --diagnose   # Detaillierte Protokolldiagnose durchführen
  $0 --test-protocol              # Verschiedene Protokollvarianten testen
EOH
    exit 0
}

# Kommandozeilenargumente verarbeiten
parse_args() {
    TEST_CONFIGS_ONLY=0
    TEST_PROTOCOL_ONLY=0
    DIAGNOSE_ONLY=0
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--device)
                DEVICE="$2"
                shift 2
                ;;
            -u|--user)
                USERNAME="$2"
                shift 2
                ;;
            -p|--password)
                PASSWORD="$2"
                shift 2
                ;;
            -i|--interval)
                POLL_INTERVAL="$2"
                shift 2
                ;;
            -o|--output)
                CSV_FILE="$2"
                shift 2
                ;;
            -D|--debug)
                DEBUG=1
                shift
                ;;
            -t|--test-configs)
                TEST_CONFIGS_ONLY=1
                shift
                ;;
            -P|--test-protocol)
                TEST_PROTOCOL_ONLY=1
                shift
                ;;
            -x|--diagnose)
                DIAGNOSE_ONLY=1
                shift
                ;;
            -r|--max-retry)
                MAX_RETRY="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                ;;
            *)
                echo "Unbekannte Option: $1"
                show_help
                ;;
        esac
    done
}

# Funktion zum Anzeigen von Debug-Informationen
debug_info() {
    if [[ "$DEBUG" -eq 1 ]]; then
        echo "[DEBUG] $@" >&2
    fi
}

# Funktion zum Testen des seriellen Ports mit spezifischen Einstellungen
test_port() {
    local baud=$1
    local device=$2
    
    echo "Teste serielle Verbindung mit $baud Baud auf $device..." >&2
    
    # Verschiedene Einstellungen testen
    stty -F $device $baud raw cs8 -cstopb -parenb -echo
    sleep 0.5
    
    # Versuche einfache Daten zu senden und zu empfangen
    echo "Sende Test-Sequenz..." >&2
    echo -ne "\x55\x55\x55" > $device
    
    # Lese Antwort
    local tmp_file=$(mktemp)
    dd if=$device of=$tmp_file bs=1 count=10 iflag=nonblock 2>/dev/null
    
    echo "Antwort auf Test-Sequenz:" >&2
    hexdump -C $tmp_file >&2
    
    rm -f $tmp_file
}

# Signal-Handler für saubere Beendigung
cleanup() {
    echo -e "\nBeende Smart Meter OSGP Reader..."
    terminate_connection
    exit 0
}

# Trap für CTRL+C
trap cleanup SIGINT SIGTERM

# Hauptskript-Steuerung mit den zusätzlichen Testoptionen
echo "Smart Meter OSGP Reader gestartet" >&2
echo "-------------------------------" >&2

# Argumente parsen
parse_args "$@"

# Abhängigkeiten prüfen
check_dependencies

echo "Konfiguration:" >&2
echo "- Gerät: $DEVICE" >&2
echo "- Benutzername: $USERNAME" >&2
echo "- Passwort: [versteckt]" >&2
echo "- Aktualisierungsintervall: $POLL_INTERVAL Sekunden" >&2
echo "- CSV-Ausgabe: $CSV_FILE" >&2
echo "- Debug-Modus: $([ "$DEBUG" -eq 1 ] && echo "Ein" || echo "Aus")" >&2
echo "- Max. Wiederholungsversuche: $MAX_RETRY" >&2
echo "-------------------------------" >&2

# CRC-Tabelle generieren
generate_crc_table

# Führe je nach Option verschiedene Modi aus
if [[ "$TEST_CONFIGS_ONLY" -eq 1 ]]; then
    echo "Nur Test der seriellen Konfigurationen wird durchgeführt..." >&2
    test_port 9600 $DEVICE
    # Test der verschiedenen Konfigurationen
    if test_serial_configs; then
        echo "Test abgeschlossen, erfolgreich!" >&2
        exit 0
    else
        echo "Test abgeschlossen, keine erfolgreiche Konfiguration gefunden." >&2
        exit 1
    fi
elif [[ "$TEST_PROTOCOL_ONLY" -eq 1 ]]; then
    echo "Nur Test der Protokollvarianten wird durchgeführt..." >&2
    # Test der verschiedenen Protokollvarianten
    if test_protocol_variants; then
        echo "Protokolltest abgeschlossen, erfolgreich!" >&2
        exit 0
    else
        echo "Protokolltest abgeschlossen, keine erfolgreiche Variante gefunden." >&2
        exit 1
    fi
elif [[ "$DIAGNOSE_ONLY" -eq 1 ]]; then
    echo "Nur detaillierte Protokolldiagnose wird durchgeführt..." >&2
    # Führe detaillierte Diagnose durch
    diagnose_protocol
    exit 0
else
    # Normaler Betriebsmodus - starte Hauptfunktion
    main
fi

# Funktion für detaillierte Protokolldiagnose
function diagnose_protocol {
    echo "Starte detaillierte Protokolldiagnose..." >&2
    
    # Erzeuge temporäre Dateien für die Protokollierung
    local diagnose_log=$(mktemp)
    local raw_log=$(mktemp)
    
    echo "Protokolldiagnose gestartet am $(date)" > "$diagnose_log"
    echo "Gerät: $DEVICE" >> "$diagnose_log"
    echo "Serielle Einstellungen: " >> "$diagnose_log"
    stty -F $DEVICE -a >> "$diagnose_log"
    
    # Testsequenz für die Diagnose
    echo "Sende verschiedene Wake-up Sequenzen für Diagnose..." | tee -a "$diagnose_log" >&2
    
    # Serielle Verbindung zurücksetzen
    if command -v stty &>/dev/null; then
        stty -F $DEVICE 0 # Reset
        sleep 0.5
    fi
    
    # Teste verschiedene Baudraten für die Diagnose
    echo "Teste Kommunikation mit verschiedenen Baudraten..." | tee -a "$diagnose_log" >&2
    
    for baudrate in 300 1200 2400 4800 9600; do
        echo "Teste mit $baudrate Baud..." | tee -a "$diagnose_log" >&2
        stty -F $DEVICE $baudrate raw cs8 -cstopb -parenb -echo
        
        # Puffer leeren
        dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=100 2>/dev/null || true
        
        # Reset serielles Gerät
        echo -ne "\x00" > $DEVICE
        sleep 0.5
        
        # Sende Wake-up Sequenz (0x55)
        for i in {1..3}; do
            echo -ne "\x55" > $DEVICE
            sleep 0.3
        done
        
        # Empfange mögliche Antworten
        echo "Empfange mögliche Antworten bei $baudrate Baud:" | tee -a "$diagnose_log" >&2
        dd if=$DEVICE of="$raw_log" bs=1 count=20 iflag=nonblock 2>/dev/null
        
        echo "Hex-Dump der empfangenen Daten:" | tee -a "$diagnose_log" >&2
        hexdump -C "$raw_log" | tee -a "$diagnose_log" >&2
        
        # Überprüfe auf bekannte Antwortmuster
        if grep -q -a "\x06" "$raw_log"; then
            echo "ACK (0x06) gefunden bei $baudrate Baud!" | tee -a "$diagnose_log" >&2
        fi
        
        if grep -q -a "\x15" "$raw_log"; then
            echo "NACK (0x15) gefunden bei $baudrate Baud!" | tee -a "$diagnose_log" >&2
        fi
        
        sleep 1
    done

    # Teste verschiedene Start-Byte-Sequenzen
    echo "Teste verschiedene Start-Byte-Sequenzen..." | tee -a "$diagnose_log" >&2
    
    # Setze Standard-Baudrate für weitere Tests
    stty -F $DEVICE 9600 raw cs8 -cstopb -parenb -echo
    
    for start_byte in '\xEE' '\xFF' '\x01' '\xFE' '\x7E'; do
        echo "Teste mit Start-Byte $start_byte..." | tee -a "$diagnose_log" >&2
        
        # Puffer leeren
        dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=100 2>/dev/null || true
        
        # Sende Start-Byte gefolgt von einer einfachen Sequenz
        echo -ne "$start_byte\x00\x00\x00\x01\x00\x20" > $DEVICE
        sleep 0.5
        
        # Empfange mögliche Antworten
        echo "Empfange mögliche Antworten für Start-Byte $start_byte:" | tee -a "$diagnose_log" >&2
        dd if=$DEVICE of="$raw_log" bs=1 count=20 iflag=nonblock 2>/dev/null
        
        echo "Hex-Dump der empfangenen Daten:" | tee -a "$diagnose_log" >&2
        hexdump -C "$raw_log" | tee -a "$diagnose_log" >&2
        
        sleep 1
    done
    
    # Fasse die Ergebnisse zusammen
    echo "Diagnose abgeschlossen. Ergebnisse wurden in $diagnose_log gespeichert." >&2
    echo "-----------------------------------------------------------" | tee -a "$diagnose_log" >&2
    echo "Empfehlungen für die weitere Fehlerbehebung:" | tee -a "$diagnose_log" >&2
    echo "1. Überprüfen Sie die physische Verbindung zum Smart Meter" | tee -a "$diagnose_log" >&2
    echo "2. Stellen Sie sicher, dass der optische Kopf korrekt ausgerichtet ist" | tee -a "$diagnose_log" >&2
    echo "3. Testen Sie verschiedene serielle Einstellungen mit --test-configs" | tee -a "$diagnose_log" >&2
    echo "4. Prüfen Sie das verwendete Protokoll (C12.18, DLMS/COSEM, etc.)" | tee -a "$diagnose_log" >&2
    echo "5. Überprüfen Sie die Benutzername/Passwort-Einstellungen des Zählers" | tee -a "$diagnose_log" >&2
    echo "-----------------------------------------------------------" | tee -a "$diagnose_log" >&2
    
    echo "Diagnoseprotokoll wurde gespeichert in: $diagnose_log" >&2
    rm -f "$raw_log"
}
