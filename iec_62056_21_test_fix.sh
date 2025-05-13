#!/bin/bash
#
# IEC 62056-21 Test-Script für Smart Meter
# Dieses Skript testet die Kommunikation mit einem Smart Meter gemäß IEC 62056-21 Standard
# der speziell für optische Schnittstellen konzipiert ist
#

# Gerät fest auf /dev/ttyUSB0
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

# Funktion zum Testen der optischen Schnittstelle gemäß IEC 62056-21
function test_iec_62056_21 {
    echo "IEC 62056-21 Test für optische Schnittstelle"
    echo "-----------------------------------------"
    
    # IEC 62056-21 unterstützt verschiedene Modi
    local modes=(
        "A"  # Mode A: 300 Baud, 7E1
        "B"  # Mode B: 300 Baud, 7E1, mit erweiterten Funktionen
        "C"  # Mode C: beginnt mit 300 Baud, wechselt dann zu höherer Baudrate
        "D"  # Mode D: beginnt mit 2400 Baud, 7E1
        "E"  # Mode E: beginnt direkt mit 9600 Baud, 7E1
    )
    
    # Baudrates für Mode C (wenn der Zähler zustimmt, wird auf höhere Baudrate umgeschaltet)
    local baudrates=(
        "1"  # 300 Baud
        "2"  # 600 Baud
        "3"  # 1200 Baud
        "4"  # 2400 Baud
        "5"  # 4800 Baud
        "6"  # 9600 Baud
    )
    
    # Herstellen einer Verbindung mit jedem Modus testen
    for mode in "${modes[@]}"; do
        echo "Teste IEC 62056-21 Mode $mode..."
        
        # Kommunikationsparameter je nach Modus einstellen
        case "$mode" in
            "A"|"B"|"C")
                # Modi A, B und C starten mit 300 Baud, 7E1
                stty -F $DEVICE 300 cs7 -cstopb parenb -parodd -echo -hupcl
                ;;
            "D")
                # Modus D startet mit 2400 Baud, 7E1
                stty -F $DEVICE 2400 cs7 -cstopb parenb -parodd -echo -hupcl
                ;;
            "E")
                # Modus E startet mit 9600 Baud, 7E1
                stty -F $DEVICE 9600 cs7 -cstopb parenb -parodd -echo -hupcl
                ;;
        esac
        
        # Puffer leeren
        dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
        sleep 1
        
        # Request-Nachricht senden
        echo "Sende Request-Message für Mode $mode..."
        
        # Das Fragezeichen-Zeichen ist Teil der IEC 62056-21-Anfrage
        cmd="/?${mode}!\r\n"
        for ((i=0; i<${#cmd}; i++)); do
            printf "\\$(printf '%03o' "'${cmd:$i:1}")" > $DEVICE
        done
        
        # Bei IEC 62056-21 Mode E können wir auch das Passwort direkt integrieren
        if [[ "$mode" == "E" ]]; then
            echo "Versuche Mode E mit Passwort..."
            # Format: /?E![Passwort]
            cmd="/?${mode}!${PASSWORD}\r\n"
            for ((i=0; i<${#cmd}; i++)); do
                printf "\\$(printf '%03o' "'${cmd:$i:1}")" > $DEVICE
            done
            sleep 1
        fi
        
        # Antwort empfangen (Identifikationsmeldung vom Zähler)
        local tmp_response=$(mktemp)
        dd if=$DEVICE of=$tmp_response bs=1 count=100 timeout=5 2>/dev/null
        
        if [[ -s "$tmp_response" ]]; then
            echo "Antwort erhalten:"
            cat "$tmp_response"
            hexdump -C "$tmp_response"
            
            # Prüfen, ob eine Identifikation vorhanden ist
            if grep -q "/[A-Za-z0-9]" "$tmp_response"; then
                echo "ERFOLG: Zähleridentifikation erkannt im Mode $mode!"
                
                # Wenn Mode C, versuche Baudrate umzuschalten
                if [[ "$mode" == "C" ]]; then
                    for baud in "${baudrates[@]}"; do
                        echo "Versuche Baudwechsel mit Geschwindigkeit $baud..."
                        
                        # Baudwechsel-Anforderung senden
                        printf "\\006${baud}0\\015\\012" > $DEVICE  # ACK + baud0 + CR + LF
                        sleep 1
                        
                        # Neue Baudrate einstellen
                        case "$baud" in
                            "1") stty -F $DEVICE 300 ;;
                            "2") stty -F $DEVICE 600 ;;
                            "3") stty -F $DEVICE 1200 ;;
                            "4") stty -F $DEVICE 2400 ;;
                            "5") stty -F $DEVICE 4800 ;;
                            "6") stty -F $DEVICE 9600 ;;
                        esac
                        
                        # Empfange Daten mit der neuen Baudrate
                        dd if=$DEVICE of=$tmp_response bs=1 count=100 timeout=5 2>/dev/null
                        
                        if [[ -s "$tmp_response" ]]; then
                            echo "Antwort nach Baudwechsel erhalten:"
                            cat "$tmp_response"
                            
                            if grep -q -a $'\x02' "$tmp_response"; then
                                echo "ERFOLG: Baudwechsel zu Rate $baud erfolgreich!"
                                echo "IEC 62056-21 Mode C mit Baudwechsel $baud funktioniert!" > successful_iec_config.txt
                                break
                            fi
                        fi
                    done
                else
                    echo "IEC 62056-21 Mode $mode funktioniert!" > successful_iec_config.txt
                fi
                
                # Daten anfragen
                echo "Fordere Daten vom Zähler an..."
                printf "\\006" > $DEVICE  # ACK senden
                sleep 1
                
                # Empfange Daten
                dd if=$DEVICE of=$tmp_response bs=1 count=1000 timeout=10 2>/dev/null
                
                echo "Empfangene Daten:"
                cat "$tmp_response"
                
                # Ende der Datenübertragung
                echo "Beende Datenübertragung..."
                printf "\\001\\102\\060\\003\\161" > $DEVICE  # EOT senden
                
                rm -f "$tmp_response"
                return 0
            fi
        fi
        
        rm -f "$tmp_response"
        sleep 2
    done
    
    echo "Keine erfolgreiche IEC 62056-21 Konfiguration gefunden."
    return 1
}

# ANSI C12.19 Tabellendefinitionen für die Datenstruktur
function test_ansi_c12_19_tables {
    echo "Teste ANSI C12.19 Tabellenzugriffe"
    echo "--------------------------------"
    
    # Konfiguriere Port für ANSI C12.18 (typischerweise 9600 8N1)
    stty -F $DEVICE 9600 raw cs8 -cstopb -parenb -echo -hupcl
    
    # Puffer leeren
    dd if=$DEVICE iflag=nonblock of=/dev/null bs=1 count=1000 2>/dev/null || true
    sleep 1
    
    # Wichtige ANSI C12.19 Tabellen (Ihre Dokumentation erwähnt ANSI C12.19 für die Datenstruktur)
    local tables=(
        "0000"  # General Configuration
        "0001"  # General Manufacturer Identification
        "0002"  # Device Identification
        "0003"  # End Device Mode & Status
        "0004"  # Pending Status
        "0007"  # Local Display List
        "0020"  # Dimension Sources Limiting
        "0021"  # Actual Register
        "0022"  # Data Selection
        "0023"  # Current Register Data
    )
    
    # Wake-up-Sequenz senden
    send_bytes 0x55 0x55 0x55 0x55 0x55
    sleep 1
    
    # Identifikation anfordern (ANSI C12.18)
    send_bytes 0xEE 0x00 0x00 0x00 0x01 0x00 0x20
    sleep 1
    
    # Authentifizierungsversuch mit Passwort
    echo "Versuche Authentifizierung mit Passwort: $PASSWORD"
    
    # Konvertiere Passwort in Byte-Array
    local password_bytes=($(string_to_bytes "$PASSWORD"))
    local password_len=${#PASSWORD}
    
    # LOGON-Request mit Passwort zusammenbauen
    local logon_bytes=(0xEE 0x00 0x00 0x00 $password_len 0x00 0x50)
    
    # Passwort-Bytes hinzufügen
    for byte in "${password_bytes[@]}"; do
        logon_bytes+=($byte)
    done
    
    # Sende LOGON-Request
    send_bytes "${logon_bytes[@]}"
    sleep 1
    
    # Empfange Antwort
    local tmp_response=$(mktemp)
    dd if=$DEVICE of=$tmp_response bs=1 count=20 timeout=2 2>/dev/null
    
    if [[ -s "$tmp_response" ]]; then
        echo "Antwort auf IDENT/LOGON-Anfrage:"
        hexdump -C "$tmp_response"
        
        # Wenn ein ACK (0x06) empfangen wurde, versuchen wir Tabellenzugriffe
        if grep -q -a $'\x06' "$tmp_response"; then
            echo "Identifikation erfolgreich, versuche Tabellenzugriffe..."
            
            for table in "${tables[@]}"; do
                echo "Versuche Zugriff auf Tabelle $table..."
                
                # Konvertiere die Tabellen-ID in Bytes
                local table_high=$((0x${table:0:2}))
                local table_low=$((0x${table:2:2}))
                
                # Sende Full Read Request (0x30) für die Tabelle
                send_bytes 0xEE 0x00 0x00 0x00 0x03 0x00 0x30 $table_low $table_high
                sleep 1
                
                # Empfange Antwort
                dd if=$DEVICE of=$tmp_response bs=1 count=100 timeout=5 2>/dev/null
                
                if [[ -s "$tmp_response" ]]; then
                    echo "Antwort für Tabelle $table:"
                    hexdump -C "$tmp_response"
                    
                    if grep -q -a $'\x06' "$tmp_response"; then
                        echo "ERFOLG: Zugriff auf Tabelle $table möglich!"
                        echo "Tabelle $table ist zugänglich." >> successful_tables.txt
                    fi
                fi
                
                sleep 1
            done
        fi
    fi
    
    rm -f "$tmp_response"
}

# Hauptfunktion
function main {
    # Prüfe, ob das Gerät existiert
    if [[ ! -e "$DEVICE" ]]; then
        echo "FEHLER: Gerät $DEVICE existiert nicht!"
        exit 1
    fi
    
    echo "Smart Meter IEC 62056-21 und ANSI C12.18/19 Test-Script"
    echo "===================================================="
    echo "Gerät: $DEVICE"
    echo "Testet Kommunikation gemäß IEC 62056-21 und ANSI C12.18/19"
    echo ""
    
    # Teste IEC 62056-21 (für optische Schnittstelle)
    test_iec_62056_21
    
    # Teste ANSI C12.19 Tabellenzugriffe
    test_ansi_c12_19_tables
    
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
