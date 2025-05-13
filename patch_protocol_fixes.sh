#!/bin/bash
#
# Smart Meter Protocol Fix Script
# Dieses Skript patcht den Smart Meter Logger, um die Unterstützung für Zähler zu verbessern,
# die nicht den Standard ANSI C12.18/19 Protokoll folgen, sondern alternative Bestätigungscodes verwenden
#

# Zieldatei
TARGET_SCRIPT="smart_meter_logger.sh"

echo "Smart Meter Protocol Fix Script"
echo "==============================="
echo "Dieses Skript patcht den Smart Meter Logger für bessere Kompatibilität mit verschiedenen Zählermodellen."
echo ""

# Prüfen, ob die Zieldatei existiert
if [ ! -f "$TARGET_SCRIPT" ]; then
    echo "FEHLER: $TARGET_SCRIPT nicht gefunden. Bitte sicherstellen, dass dieses Skript im selben Verzeichnis wie smart_meter_logger.sh ausgeführt wird."
    exit 1
fi

echo "Sicherungskopie erstellen..."
cp "$TARGET_SCRIPT" "${TARGET_SCRIPT}.backup"
echo "Backup erstellt: ${TARGET_SCRIPT}.backup"
echo ""

echo "Führe Patches durch..."

# Patch 1: Verbessere den wait_for_ack-Teil, um 0xFF und 0xE5 als gültige Bestätigungen zu akzeptieren
# Zeile finden, die den ACK-Check enthält
awk '
    /local response=\$\(hexdump -v -e '"'"'1\/1 "%02X"'"'"' "\$tmp_file"\)/ {
        print "            local first_byte=$(hexdump -v -e '"'"'1/1 \"%02X\""'"'"' -n 1 \"$tmp_file\")"
        print "            local all_bytes=$(hexdump -v -e '"'"'1/1 \"%02X \""'"'"' \"$tmp_file\")"
        print "            "
        print "            log_message \"Antwort empfangen: $all_bytes (erster Byte: 0x$first_byte)\""
        print "            "
        next
    }
    /if \[\[ "\$response" == "06" \]\]; then/ {
        print "            if [[ \"$first_byte\" == \"06\" ]]; then  # Standard ACK"
        print "                log_message \"Standard ACK (0x06) empfangen\""
        print "                rm -f \"$tmp_file\""
        print "                return 0"
        print "            elif [[ \"$first_byte\" == \"15\" ]]; then  # NACK erhalten"
        print "                log_message \"NACK (0x15) empfangen, Versuch $attempt von $max_attempts\""
        print "                if [[ $attempt -lt $max_attempts ]]; then"
        print "                    sleep 1"
        print "                    continue"
        print "                fi"
        print "            elif [[ \"$first_byte\" == \"00\" || \"$first_byte\" == \"FF\" || \"$first_byte\" == \"E5\" ]]; then "
        print "                # Manche Zähler senden 0x00, 0xFF oder 0xE5 als Bestätigung"
        print "                log_message \"Alternative Bestätigung (0x$first_byte) empfangen, wird als ACK akzeptiert\""
        print "                rm -f \"$tmp_file\""
        print "                return 0"
        print "            elif [[ \"$first_byte\" == \"$START_BYTE\" ]]; then"
        print "                # Der Zähler hat direkt mit einer vollständigen Antwort geantwortet"
        print "                log_message \"Vollständige Antwort erhalten (beginnt mit START_BYTE)\""
        print "                rm -f \"$tmp_file\""
        print "                return 0"
        print "            else"
        print "                log_message \"Unerwartete Antwort: 0x$first_byte, versuche als ACK zu akzeptieren\""
        print "                # Im Debug-Modus akzeptieren wir jede Antwort als Erfolg"
        print "                if [[ \"$DEBUG_SCAN\" == \"true\" ]]; then"
        print "                    rm -f \"$tmp_file\""
        print "                    return 0"
        print "                fi"
        print "            fi"
        next
    }
    /elif \[\[ "\$response" == "15" \]\]; then/ { next }  # Skip these lines
    /elif \[\[ "\$response" == "00" \]\]; then/ { next }  # Skip these lines
    { print }
' "${TARGET_SCRIPT}.backup" > "${TARGET_SCRIPT}"

echo "Patch abgeschlossen!"
echo ""
echo "Bitte teste nun das gepatche Skript mit dem Zähler."
echo "Bei Problemen kann die Backup-Version wiederhergestellt werden mit:"
echo "  cp ${TARGET_SCRIPT}.backup ${TARGET_SCRIPT}"
echo ""
echo "Für einfacheres Testen verschiedener Protokollvarianten verwende auch:"
echo "  ./direct_scan.sh [/dev/ttyUSB0]"
