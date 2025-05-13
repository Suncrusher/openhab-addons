#!/bin/bash
#
# Smart Meter 9600 Baud Test-Script
# Dieses Skript testet die Kommunikation mit einem Smart Meter speziell mit 9600 Baud
# und verschiedenen Varianten und Parität
#

# Gerät fest auf /dev/ttyUSB0 eingestellt
DEVICE="/dev/ttyUSB0"

# Passwort für die Authentifizierung (für passwortgeschützte Kommunikation)
PASSWORD="00000000"  # Standard-Passwort, oft 8 Nullen

# Hilfsfunktion zum sicheren Senden von Hex-Bytes
send_bytes() {
    local tmp_file=$(mktemp)
    
    # Debug-Ausgabe
    echo -n "Sende: " >&2
    for byte in "$@"; do
        # Sicherstellen, dass der Wert eine Zahl ist (keine Hex-Strings wie 0xNN)
        if [[ $byte =~ ^0x ]]; then
            byte=$((byte))
        fi
        printf "%02X " $byte >&2
        printf "\\$(printf '%03o' $byte)" >> "$tmp_file"
    done
    echo "" >&2
    
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

# Verbesserte 9600 Baud Optimierung für optische Koppler
function test_9600_baud_options {
    echo "Spezifischer Test für 9600 Baud (Standard laut Handbuch)"
    echo "------------------------------------------------------"
    
    # Verschiedene Paritätseinstellungen mit 9600 Baud
    local parity_settings=(
        "-parenb"         # Keine Parität (8N1)
        "parenb -parodd"  # Gerade Parität (8E1)
        "parenb parodd"   # Ungerade Parität (8O1)
    )
    
    # Verschiedene Hardware-Flow-Control Einstellungen
    local flow_settings=(
        ""           # Kein Flow Control
        "-crtscts"   # Kein Hardware Flow Control
        "crtscts"    # Hardware Flow Control
    )
    
    # Verschiedene Stop-Bit Einstellungen
    local stop_settings=(
        "-cstopb"    # 1 Stop-Bit
        "cstopb"     # 2 Stop-Bits
    )
    
    # Verschiedene Start-Bytes für den C12.18 Header (ANSI C12.18 2006)
    local start_bytes=(
        0xEE  # Standard für ANSI C12.18
        0xFF  # Alternativ
        0x01  # Vereinfacht
        0x2F  # IEC 62056-21 Start-Byte (/)
    )
    
    # Verschiedene Identity-Bytes
    local identity_bytes=(
        0x00  # Standard
        0x01  # Alternativ
        0x3F  # IEC 62056-21 Identity (?)
    )
    
    for parity in "${parity_settings[@]}"; do
        for flow in "${flow_settings[@]}"; do
            for stop in "${stop_settings[@]}"; do
                echo "Teste 9600 Baud mit: $parity $flow $stop"
                
                # Serielle Schnittstelle konfigurieren
                stty -F $DEVICE 9600 raw cs8 $stop $parity $flow -echo -hupcl
                
                # Puffer leeren
                dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
                sleep 1
                
                # Erweiterte Wake-up Sequenz
                echo "Sende erweiterte Wake-up Sequenz..."
                for i in {1..3}; do
                    # 0x55 ist ein gutes Synchronisierungsmuster (01010101)
                    send_bytes 0x55 0x55 0x55 0x55 0x55
                    sleep 1
                    
                    # Pause zum Umschalten der Richtung (bei optischen Kopplern wichtig)
                    sleep 0.5
                done
                
                for start_byte in "${start_bytes[@]}"; do
                    for identity_byte in "${identity_bytes[@]}"; do
                        # Start-Byte in Hex für Ausgabe umwandeln
                        local start_byte_val=$((start_byte))
                        local identity_byte_val=$((identity_byte))
                        local start_byte_hex=$(printf "%02X" $start_byte_val)
                        local identity_byte_hex=$(printf "%02X" $identity_byte_val)
                        
                        echo "Teste mit Start-Byte: 0x$start_byte_hex, Identity-Byte: 0x$identity_byte_hex"
                        
                        # Prüfen, ob wir IEC 62056-21 Format verwenden sollen
                        if [[ "$start_byte" == "0x2F" && "$identity_byte" == "0x3F" ]]; then
                            # IEC 62056-21 Format (/?!\r\n für Mode C oder /?E\r\n für Mode E)
                            printf "/?\!\r\n" > $DEVICE  # Mode C (300 Baud initial)
                            sleep 2
                            printf "/?E\r\n" > $DEVICE   # Mode E (direkt mit höherer Baudrate)
                        else
                            # Standard ANSI C12.18 Format
                            send_bytes $start_byte_val $identity_byte_val 0x00 0x00 0x01 0x00 0x20
                            
                            # Bei passwortgeschützter Kommunikation versuchen wir auch einen Authentifizierungsversuch
                            if [[ $start_byte == "0xEE" ]]; then
                                sleep 1
                                echo "Versuche Authentifizierung mit Standard-Passwort..."
                                
                                # Konvertiere Passwort in Byte-Array
                                local password_bytes=($(string_to_bytes "$PASSWORD"))
                                local password_len=${#PASSWORD}
                                
                                # LOGON-Request mit Passwort zusammenbauen
                                local logon_bytes=($start_byte_val $identity_byte_val 0x00 0x00 $password_len 0x00 0x50)
                                
                                # Passwort-Bytes hinzufügen
                                for byte in "${password_bytes[@]}"; do
                                    logon_bytes+=($byte)
                                done
                                
                                # Sende LOGON-Request
                                send_bytes "${logon_bytes[@]}"
                                echo "Auth-Request mit Passwort ($PASSWORD) gesendet"
                            fi
                        fi
                        sleep 1
                        
                        # Empfange Antwort
                        local tmp_response=$(mktemp)
                        dd if=$DEVICE of=$tmp_response bs=1 count=20 iflag=nonblock 2>/dev/null
                        
                        if [[ -s "$tmp_response" ]]; then
                            echo "Antwort erhalten:"
                            hexdump -C "$tmp_response"
                            
                            # Prüfe auf ACK oder NACK
                            if grep -q -a $'\x06' "$tmp_response"; then
                                echo "ERFOLG: ACK gefunden mit folgender Konfiguration:"
                                echo "- 9600 Baud mit $parity $flow $stop"
                                echo "- Start-Byte: 0x$start_byte_hex"
                                echo "- Identity-Byte: 0x$identity_byte_hex"
                                
                                # Speichere erfolgreiche Konfiguration
                                echo "9600 raw cs8 $stop $parity $flow -echo -hupcl" > successful_config.txt
                                echo "$start_byte" >> successful_config.txt
                                echo "$identity_byte" >> successful_config.txt
                                
                                echo "Konfiguration wurde in successful_config.txt gespeichert"
                                rm -f "$tmp_response"
                                return 0
                            fi
                            
                            if grep -q -a $'\x15' "$tmp_response"; then
                                echo "NACK erhalten - Zähler hat den Befehl erkannt, aber abgelehnt"
                                echo "Dies könnte ein Authentifizierungsproblem sein oder ein Problem mit den Parametern"
                                
                                # Versuche mit anderem Request-Typ
                                echo "Versuche mit NEGOTIATE-Request (0x61)..."
                                send_bytes $start_byte_val $identity_byte_val 0x00 0x00 0x01 0x00 0x61
                                sleep 1
                                
                                # Empfange Antwort
                                dd if=$DEVICE of=$tmp_response bs=1 count=20 iflag=nonblock 2>/dev/null
                                echo "Antwort auf NEGOTIATE-Request:"
                                hexdump -C "$tmp_response"
                            fi
                        fi
                        
                        rm -f "$tmp_response"
                        sleep 1
                    done
                done
            done
        done
    done
    
    echo "Keine erfolgreiche Konfiguration gefunden."
    return 1
}

# Funktion zum Senden einer reinen Raw-Sequenz für spezielle Zähler
function send_special_sequences {
    echo "Sende spezielle Sequenzen für problematische Zähler"
    echo "--------------------------------------------------"
    
    # Konfiguriere Port mit Standard 9600 8N1 (IEC 62056-21 Standard)
    stty -F $DEVICE 9600 raw cs8 -cstopb -parenb -echo -hupcl
    
    # Puffer leeren
    dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
    sleep 1
    
    # Spezielle Sequenzen, die bei manchen Zählermodellen funktionieren
    # Definiere die Sequenzen als Arrays von Dezimalwerten für unsere send_bytes Funktion
    local ee_ident=(0xEE 0x00 0x00 0x00 0x01 0x00 0x20 0x93 0x72)
    local ff_ident=(0xFF 0x00 0x00 0x00 0x01 0x00 0x20 0x17 0x53)
    local simple_ident=(0xEE 0x00 0x00 0x00 0x01 0x00 0x20)
    local ext_ident=(0xEE 0x00 0x00 0x00 0x08 0x00 0x30 0x00 0x00 0x00 0x00 0x00 0x00 0x00)
    local dlms_wake=(0x7E 0xA0 0x00 0x01 0x00 0x00 0x00 0x7E)
    # Diese werden direkt als Strings gesendet
    local iec_c="/?!\r\n"
    local iec_e="/?E\r\n"
    
    # Teste zuerst die binären Sequenzen
    for seq_name in ee_ident ff_ident simple_ident ext_ident dlms_wake; do
        # Dynamische Variablenreferenz verwenden, um auf das Array zuzugreifen
        seq_var="${seq_name}[@]"
        seq_bytes=("${!seq_var}")
        
        echo "Teste spezielle Sequenz: $seq_name"
        
        # Sende Wake-up
        send_bytes 0x55 0x55 0x55 0x55 0x55
        sleep 1
        
        # Sende Sequenz
        send_bytes "${seq_bytes[@]}"
        sleep 1
        
        # Empfange Antwort
        local tmp_response=$(mktemp)
        dd if=$DEVICE of=$tmp_response bs=1 count=20 iflag=nonblock 2>/dev/null
        
        if [[ -s "$tmp_response" ]]; then
            echo "Antwort erhalten:"
            hexdump -C "$tmp_response"
            
            # Prüfe auf jegliche Antwort
            if [[ -s "$tmp_response" ]]; then
                echo "Diese Sequenz erzeugt eine Antwort!"
                echo "Sequenz: $seq_name" > special_sequence.txt
                echo "Sequenz wurde in special_sequence.txt gespeichert"
            fi
        fi
        
        rm -f "$tmp_response"
        sleep 2
    done
    
    # Teste IEC 62056-21 Text-Protokoll-Sequenzen
    for seq in "$iec_c" "$iec_e"; do
        echo "Teste IEC 62056-21 Sequenz: $(echo -n "$seq" | xxd -p)"
        
        # Sende Wake-up
        send_bytes 0x55 0x55 0x55 0x55 0x55
        sleep 1
        
        # Sende die Text-Sequenz direkt
        echo -n "$seq" > $DEVICE
        sleep 1
        
        # Empfange Antwort
        local tmp_response=$(mktemp)
        dd if=$DEVICE of=$tmp_response bs=1 count=20 iflag=nonblock 2>/dev/null
        
        if [[ -s "$tmp_response" ]]; then
            echo "Antwort erhalten:"
            hexdump -C "$tmp_response"
            
            # Prüfe auf jegliche Antwort
            if [[ -s "$tmp_response" ]]; then
                echo "Diese Sequenz erzeugt eine Antwort!"
                echo "Sequenz: $(echo -n "$seq" | xxd -p)" > special_sequence.txt
                echo "Sequenz wurde in special_sequence.txt gespeichert"
            fi
        fi
        
        rm -f "$tmp_response"
        sleep 2
    done
}

# Hauptfunktion
function main {
    # Prüfe, ob das Gerät existiert
    if [[ ! -e "$DEVICE" ]]; then
        echo "FEHLER: Gerät $DEVICE existiert nicht!"
        exit 1
    fi
    
    echo "Smart Meter 9600 Baud Test-Script"
    echo "==============================="
    echo "Gerät: $DEVICE"
    echo "Testet verschiedene Kommunikationsoptionen mit 9600 Baud"
    echo ""
    
    # Teste zunächst die 9600 Baud Optionen
    test_9600_baud_options
    
    # Wenn das nicht funktioniert, versuche spezielle Sequenzen
    echo ""
    echo "Starte Test mit speziellen Sequenzen..."
    send_special_sequences
    
    echo ""
    echo "Tests abgeschlossen."
    echo "Prüfen Sie die Ausgabe auf erfolgreiche Konfigurationen."
}

# Kommandozeilenargumente verarbeiten
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Verwendung: $0 [--password PASSWORT]"
    echo ""
    echo "Optionen:"
    echo "  --password, -p PASSWORT  Das zu verwendende Passwort (Standard: 00000000)"
    echo "  --help, -h               Diese Hilfe anzeigen"
    exit 0
fi

# Gerät ist fest auf /dev/ttyUSB0 eingestellt
# Aber Passwort kann konfiguriert werden
if [[ "$1" == "--password" || "$1" == "-p" ]]; then
    if [[ -n "$2" ]]; then
        PASSWORD="$2"
        echo "Verwende Passwort: $PASSWORD"
    else
        echo "FEHLER: Nach --password muss ein Passwort angegeben werden!"
        exit 1
    fi
fi

# Starte Hauptfunktion
main
