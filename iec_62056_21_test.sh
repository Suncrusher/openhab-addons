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
        echo -ne "/?$mode!\r\n" > $DEVICE
        
        # Bei IEC 62056-21 Mode E können wir auch das Passwort direkt integrieren
        if [[ "$mode" == "E" ]]; then
            echo "Versuche Mode E mit Passwort..."
            # Format: /[Zählernummer]![Passwort]
            echo -ne "/?$mode!$PASSWORD\r\n" > $DEVICE
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
                        echo -ne "\x06${baud}0\r\n" > $DEVICE
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
                            
                            if grep -q "\x02" "$tmp_response"; then
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
                echo -ne "\x06" > $DEVICE  # ACK senden
                sleep 1
                
                # Empfange Daten
                dd if=$DEVICE of=$tmp_response bs=1 count=1000 timeout=10 2>/dev/null
                
                echo "Empfangene Daten:"
                cat "$tmp_response"
                
                # Ende der Datenübertragung
                echo "Beende Datenübertragung..."
                echo -ne "\x01\x42\x30\x03\x71" > $DEVICE  # EOT senden
                
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
    echo -ne "\x55\x55\x55\x55\x55" > $DEVICE
    sleep 1
    
    # Identifikation anfordern (ANSI C12.18)
    echo -ne "\xEE\x00\x00\x00\x01\x00\x20" > $DEVICE
    sleep 1
    
    # Authentifizierungsversuch mit Passwort
    echo "Versuche Authentifizierung mit Passwort: $PASSWORD"
    
    # Direktere und sicherere Methode zur Passwortübertragung
    # Erstelle eine temporäre Datei mit den Bytes
    local auth_request=$(mktemp)
    
    # Header schreiben
    printf "\xEE\x00\x00\x00" > $auth_request
    
    # Länge schreiben
    password_len=${#PASSWORD}
    printf "$(printf "\\x%02x" $password_len)" >> $auth_request
    
    # Restlicher Header
    printf "\x00\x50" >> $auth_request
    
    # Passwort schreiben - Zeichen für Zeichen um printf-Fehler zu vermeiden
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
    sleep 1
    
    # Empfange Antwort
    local tmp_response=$(mktemp)
    dd if=$DEVICE of=$tmp_response bs=1 count=20 timeout=2 2>/dev/null
    
    if [[ -s "$tmp_response" ]]; then
        echo "Antwort auf IDENT-Anfrage:"
        hexdump -C "$tmp_response"
        
        # Wenn ein ACK (0x06) empfangen wurde, versuchen wir Tabellenzugriffe
        if grep -q -a "\x06" "$tmp_response"; then
            echo "Identifikation erfolgreich, versuche Tabellenzugriffe..."
            
            for table in "${tables[@]}"; do
                echo "Versuche Zugriff auf Tabelle $table..."
                
                # Konvertiere String zu Hex-Bytes
                local table_high=$(echo "$table" | cut -c1-2)
                local table_low=$(echo "$table" | cut -c3-4)
                
                # Erstelle eine temporäre Datei für den Befehl
                local table_request=$(mktemp)
                
                # Format: START IDENTITY CONTROL RESERVED LENGTH_LOW LENGTH_HIGH COMMAND TABLE_ID_LOW TABLE_ID_HIGH
                # Schreibe die Bytes nacheinander, um printf-Fehler zu vermeiden
                printf "\xEE\x00\x00\x00\x03\x00\x30" > $table_request
                
                # Konvertiere die Tabellen-IDs zu Hex und schreibe sie
                printf "$(printf "\\x%02x" 0x$table_low)" >> $table_request
                printf "$(printf "\\x%02x" 0x$table_high)" >> $table_request
                
                # Sende den vollständigen Befehl zum Gerät
                cat $table_request > $DEVICE
                rm -f $table_request
                sleep 1
                
                # Empfange Antwort
                dd if=$DEVICE of=$tmp_response bs=1 count=100 timeout=5 2>/dev/null
                
                if [[ -s "$tmp_response" ]]; then
                    echo "Antwort für Tabelle $table:"
                    hexdump -C "$tmp_response"
                    
                    if grep -q -a "\x06" "$tmp_response"; then
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
