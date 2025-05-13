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
    
    # Passwort für Authentication (laut Ihrer Dokumentation passwortgeschützt)
    # Wir verwenden die globale Variable PASSWORD
    
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
                    echo -ne "\x55\x55\x55\x55\x55" > $DEVICE
                    sleep 1
                    
                    # Pause zum Umschalten der Richtung (bei optischen Kopplern wichtig)
                    sleep 0.5
                done
                
                for start_byte in "${start_bytes[@]}"; do
                    for identity_byte in "${identity_bytes[@]}"; do
                        # Start-Byte in Hex für Ausgabe umwandeln
                        local start_byte_hex=$(printf "%02X" $start_byte)
                        local identity_byte_hex=$(printf "%02X" $identity_byte)
                        
                        echo "Teste mit Start-Byte: 0x$start_byte_hex, Identity-Byte: 0x$identity_byte_hex"
                        
                        # Sende einfachen C12.18 Header mit IDENT-Request (0x20)
                        # Format: START IDENTITY CONTROL RESERVED LENGTH_LOW LENGTH_HIGH COMMAND
                        
                        # Prüfen, ob wir IEC 62056-21 Format verwenden sollen
                        if [[ "$start_byte" == "0x2F" && "$identity_byte" == "0x3F" ]]; then
                            # IEC 62056-21 Format (/?!\r\n für Mode C oder /?E\r\n für Mode E)
                            echo -ne "/?\!\\r\\n" > $DEVICE   # Mode C (300 Baud initial)
                            sleep 2
                            echo -ne "/?E\\r\\n" > $DEVICE    # Mode E (direkt mit höherer Baudrate)
                        else
                            # Standard ANSI C12.18 Format - Sichere Formatierung mit temporärer Datei
                            local ident_request=$(mktemp)
                            
                            # Header Teil für Teil schreiben
                            printf "$(printf "\\x%02x" $start_byte)" > $ident_request
                            printf "$(printf "\\x%02x" $identity_byte)" >> $ident_request
                            printf "\x00\x00\x01\x00\x20" >> $ident_request
                            
                            # Sende den Befehl
                            cat $ident_request > $DEVICE
                            rm -f $ident_request
                            
                            # Bei passwortgeschützter Kommunikation versuchen wir auch einen Authentifizierungsversuch
                            if [[ $start_byte == "0xEE" ]]; then
                                sleep 1
                                echo "Versuche Authentifizierung mit Standard-Passwort..."
                                # Sende LOGON-Request (0x50) mit Passwort
                                # Erstelle eine temporäre Datei mit den Bytes für den Authentifizierungsbefehl
                                local auth_request=$(mktemp)
                                
                                # Start-Byte und Identity-Byte schreiben
                                printf "$(printf "\\x%02x" $start_byte)" > $auth_request
                                printf "$(printf "\\x%02x" $identity_byte)" >> $auth_request
                                
                                # Kontroll-Byte und Reserved
                                printf "\x00\x00" >> $auth_request
                                
                                # Länge des Passworts
                                password_len=${#PASSWORD}
                                printf "$(printf "\\x%02x" $password_len)" >> $auth_request
                                
                                # Restlicher Header (High-Length und Kommando)
                                printf "\x00\x50" >> $auth_request
                                
                                # Passwort Zeichen für Zeichen schreiben
                                for (( i=0; i<${#PASSWORD}; i++ )); do
                                    char="${PASSWORD:$i:1}"
                                    # Vermeide Fehler mit Sonderzeichen
                                    if [[ $(printf "%d" "'$char" 2>/dev/null) ]]; then
                                        printf "$(printf "\\x%02x" "'$char")" >> $auth_request
                                    else
                                        printf "\x3F" >> $auth_request  # Fragezeichen für nicht-druckbare Zeichen
                                    fi
                                done
                                
                                # Sende den vollständigen Befehl zum Gerät
                                cat $auth_request > $DEVICE
                                rm -f $auth_request
                                
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
                            if grep -q -a "\x06" "$tmp_response"; then
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
                            
                            if grep -q -a "\x15" "$tmp_response"; then
                                echo "NACK erhalten - Zähler hat den Befehl erkannt, aber abgelehnt"
                                echo "Dies könnte ein Authentifizierungsproblem sein oder ein Problem mit den Parametern"
                                
                                # Versuche mit anderem Request-Typ
                                echo "Versuche mit NEGOTIATE-Request (0x61)..."
                                
                                # Sichere Methode mit temporärer Datei
                                local neg_request=$(mktemp)
                                
                                # Header Teil für Teil schreiben
                                printf "$(printf "\\x%02x" $start_byte)" > $neg_request
                                printf "$(printf "\\x%02x" $identity_byte)" >> $neg_request
                                printf "\x00\x00\x01\x00\x61" >> $neg_request
                                
                                # Sende den Befehl
                                cat $neg_request > $DEVICE
                                rm -f $neg_request
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
    local special_sequences=(
        # Standard C12.18 IDENT mit manuellem CRC (ANSI C12.18 2006)
        "\xEE\x00\x00\x00\x01\x00\x20\x93\x72"
        # Alternative IDENT-Sequenz 
        "\xFF\x00\x00\x00\x01\x00\x20\x17\x53"
        # Vereinfachtes Format ohne CRC
        "\xEE\x00\x00\x00\x01\x00\x20"
        # ANSI C12.18 extended IDENT mit Authentifizierungsfeld
        "\xEE\x00\x00\x00\x08\x00\x30\x00\x00\x00\x00\x00\x00\x00"
        # DLMS/COSEM Wake-up (IEC 62056-21)
        "\x7E\xA0\x00\x01\x00\x00\x00\x7E"
        # IEC 62056-21 Mode C (für optische Schnittstelle)
        "\x2F\x3F\x21\x0D\x0A"
        # IEC 62056-21 Mode E (für optische Schnittstelle)
        "\x2F\x3F\x45\x0D\x0A"
    )
    
    for seq in "${special_sequences[@]}"; do
        echo "Teste spezielle Sequenz: $(echo -n "$seq" | xxd -p)"
        
        # Sende Wake-up
        echo -ne "\x55\x55\x55\x55\x55" > $DEVICE
        sleep 1
        
        # Sende Sequenz
        echo -ne "$seq" > $DEVICE
        sleep 1
        
        # Empfange Antwort
        local tmp_response=$(mktemp)
        dd if=$DEVICE of=$tmp_response bs=1 count=20 iflag=nonblock 2>/dev/null
        
        if [[ -s "$tmp_response" ]]; then
            echo "Antwort erhalten:"
            hexdump -C "$tmp_response"
            
            # Prüfe auf jegliche Antwort - bei Spezialsequenzen kann das Format variieren
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
