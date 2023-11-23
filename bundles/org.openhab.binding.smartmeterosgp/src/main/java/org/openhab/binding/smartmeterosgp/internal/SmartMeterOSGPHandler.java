/**
 * Copyright (c) 2010-2023 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.smartmeterosgp.internal;

import static org.openhab.binding.smartmeterosgp.internal.SmartMeterOSGPBindingConstants.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.core.io.transport.serial.PortInUseException;
import org.openhab.core.io.transport.serial.SerialPort;
import org.openhab.core.io.transport.serial.SerialPortIdentifier;
import org.openhab.core.io.transport.serial.SerialPortManager;
import org.openhab.core.io.transport.serial.UnsupportedCommOperationException;
import org.openhab.core.library.types.QuantityType;
import org.openhab.core.library.unit.Units;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.openhab.core.thing.binding.BaseThingHandler;
import org.openhab.core.types.Command;
import org.openhab.core.types.RefreshType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@link SmartMeterOSGPHandler} is responsible for handling commands, which are
 * sent to one of the channels.
 *
 * @author Kennet Nielsen - Initial contribution
 */
@NonNullByDefault
public class SmartMeterOSGPHandler extends BaseThingHandler {

    private final Logger logger = LoggerFactory.getLogger(SmartMeterOSGPHandler.class);
    private final SerialPortManager serialPortManager;
    private @Nullable SerialPort serialPort;

    public @Nullable InputStream inputStream;
    public @Nullable OutputStream outputStream;

    private @Nullable SmartMeterOSGPConfiguration config;
    private @Nullable ScheduledFuture<?> pollingJob = null;

    enum ConnectState {
        Init,
        Connected
    };

    public ConnectState connectState = ConnectState.Init;
    private CRC16 crc16Calc = new CRC16(CRC16.Polynom.CRC16_CCIT);

    private ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;
    private boolean toggleControl = false;
    private long lastLogonTime = 0;

    public SmartMeterOSGPHandler(Thing thing, final SerialPortManager serialPortManager) {
        super(thing);
        this.serialPortManager = serialPortManager;
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
        if (CHANNEL_Fwd_active_power.equals(channelUID.getId())) {
            if (command instanceof RefreshType) {
                // TODO: handle data refresh
            }

            // TODO: handle command

            // Note: if communication with thing fails for some reason,
            // indicate that by setting the status with detail information:
            // updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR,
            // "Could not control device at IP address x.x.x.x");
        }
    }

    @Override
    public void initialize() {
        config = getConfigAs(SmartMeterOSGPConfiguration.class);

        final String port = config.port;
        if (port == null) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.OFFLINE.CONFIGURATION_ERROR, "Port must be set!");
            return;
        }

        // parse ports and if the port is found, initialize the reader
        final SerialPortIdentifier portId = serialPortManager.getIdentifier(config.port);
        if (portId == null) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.OFFLINE.CONFIGURATION_ERROR, "Port is not known!");
            return;
        }

        // initialize serial port
        try {
            final SerialPort serialPort = portId.open(getThing().getUID().toString(), 2000);
            this.serialPort = serialPort;

            serialPort.enableReceiveThreshold(1);
            serialPort.enableReceiveTimeout(2000);

            inputStream = serialPort.getInputStream();
            outputStream = serialPort.getOutputStream();
            serialPort.setRTS(true);
            serialPort.setDTR(false);
            logger.info("SerialPort {} Baud {} Databits {} StopBits {} Parity {} RTS {} DTR {} userId {} Username {}",
                    portId.getName(), serialPort.getBaudRate(), serialPort.getDataBits(), serialPort.getStopBits(),
                    serialPort.getParity(), serialPort.isRTS(), serialPort.isDTR(), config.userId, config.username);
            updateStatus(ThingStatus.UNKNOWN);
            pollingJob = scheduler.scheduleWithFixedDelay(this::pollStatus, 0, config.refreshInterval,
                    TimeUnit.SECONDS);

        } catch (final IOException ex) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR, "I/O error!");
        } catch (PortInUseException e) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.OFFLINE.CONFIGURATION_ERROR, "Port is in use!");
        } catch (UnsupportedCommOperationException e) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.OFFLINE.CONFIGURATION_ERROR,
                    "Serial port does not support receive threshold or receive timeout");
        }

        // These logging types should be primarily used by bindings
        // logger.trace("Example trace message");
        // logger.debug("Example debug message");
        // logger.warn("Example warn message");
        //
        // Logging to INFO should be avoided normally.
        // See https://www.openhab.org/docs/developer/guidelines.html#f-logging

        // Note: When initialization can NOT be done set the status with more details for further
        // analysis. See also class ThingStatusDetail for all available status details.
        // Add a description to give user information to understand why thing does not work as expected. E.g.
        // updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
        // "Can not access device as username and/or password are invalid");
    }

    @Override
    public void dispose() {
        final @Nullable ScheduledFuture<?> pollingJob = this.pollingJob;
        if (pollingJob != null) {
            pollingJob.cancel(true);
            this.pollingJob = null;
        }
        final @Nullable SerialPort serialPort = this.serialPort;
        if (serialPort != null) {
            serialPort.close();
            this.serialPort = null;
        }
        final InputStream inputStream = this.inputStream;
        if (inputStream != null) {
            try {
                inputStream.close();
            } catch (final IOException e) {
                logger.warn("Error while closing the input stream: {}", e.getMessage());
            }
            this.inputStream = null;
        }

        final OutputStream outputStream = this.outputStream;
        if (outputStream != null) {
            try {
                outputStream.close();
            } catch (final IOException e) {
                logger.warn("Error while closing the output stream: {}", e.getMessage());
            }
            this.outputStream = null;
        }
    }

    public String bb2hex(ByteBuffer bb) {
        return bb2hex(bb.array(), bb.limit());
    }

    public String bb2hex(byte[] bb) {
        return bb2hex(bb, bb.length);
    }

    public String bb2hex(byte[] bb, int length) {
        if (bb == null) {
            return "null value ";
        }
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < length; i++) {
            result.append(String.format("%02X ", bb[i]));
        }
        return result.toString();
    }

    public boolean sendRequestID(byte request) {
        if (!sendMsg(new byte[] { request }, false, false))
            return false;
        if (receiveMsgAndCheckAck() == null)
            return false;
        return true;
    }

    public boolean sendNegotiateRequest() {
        ByteBuffer msg = ByteBuffer.allocate(1 + 4);
        msg.put(RequestID_Negotiate2);
        msg.putShort((short) 64); // maximum packet size
        msg.put((byte) 0x02); // maximum packets for reassembly
        msg.put((byte) (C1218_Baudrate.Baud_9600.ordinal()));
        if (!sendMsg(msg.array()))
            return false;
        if (receiveMsgAndCheckAck() == null)
            return false;
        return true;
    }

    public boolean sendLogonRequest(short userId, String username) {
        ByteBuffer msg = ByteBuffer.allocate(1 + 12);
        msg.put(RequestID_Logon);
        msg.putShort(userId);

        for (int n = 0; n < username.length(); n++)
            msg.put((byte) username.charAt(n));
        while (msg.hasRemaining())
            msg.put((byte) ' ');
        if (!sendMsg(msg.array()))
            return false;
        if (receiveMsgAndCheckAck() == null)
            return false;
        return true;
    }

    public boolean sendSecurityRequest(String password) {
        ByteBuffer msg = ByteBuffer.allocate(1 + 20);
        msg.put(RequestID_Security);
        int n = 0;
        for (; n < password.length(); n++)
            msg.put((byte) password.charAt(n));
        for (; n < 20; n++)
            msg.put((byte) 0);
        if (!sendMsg(msg.array(), true, true))
            return false;
        if (receiveMsgAndCheckAck() == null)
            return false;
        return true;
    }

    public @Nullable ByteBuffer sendReadTable(int tabel) {
        ByteBuffer msg = ByteBuffer.allocate(3);
        msg.put(RequestID_Read);
        msg.putShort((short) tabel);
        if (!sendMsg(msg.array()))
            return null;
        return receiveMsgAndCheckAck();
    }

    public @Nullable ByteBuffer sendReadPartialTable(int tabel, int offset, int bytes) {
        ByteBuffer msg = ByteBuffer.allocate(8);
        msg.put(RequestID_ReadPartial);
        msg.putShort((short) tabel);
        msg.put((byte) (offset >> 16));
        msg.putShort((short) offset);
        msg.putShort((short) bytes);
        if (!sendMsg(msg.array()))
            return null;
        return receiveMsgAndCheckAck();
    }

    private boolean sendMsg(byte[] send) {
        return sendMsg(send, false, true);
    }

    private boolean sendMsg(byte[] message, boolean hideContens, boolean logInitialError) {
        ByteBuffer msg = ByteBuffer.allocate(message.length + 8);
        msg.put(START);
        msg.put(IDENTITY);
        msg.put((byte) (toggleControl ? 0x20 : 0x00));
        msg.put((byte) 0);// sequence
        msg.putShort((short) message.length);
        toggleControl = !toggleControl;
        msg.put(message);
        int crc = crc16Calc.calculate(msg.array(), msg.position(), 0xFFFF) ^ 0xFFFF;
        msg.order(ByteOrder.LITTLE_ENDIAN);
        msg.putShort((short) crc);
        final byte[] send = msg.array();
        String sendLog = hideContens ? "<Hidden>" : bb2hex(send);
        try {
            for (int pktcount = 0; pktcount < 3; pktcount++) {
                if (inputStream.available() > 0) {
                    byte[] unknown = inputStream.readNBytes(inputStream.available());
                    if (logInitialError) {
                        logger.warn("Received unknown data {}", bb2hex(unknown));
                    } else {
                        logger.trace("Received unknown data {}", bb2hex(unknown));
                    }
                }
                logger.trace("Sending {}", sendLog);
                if (pktcount > 0)
                    logInitialError = true;
                outputStream.write(send);
                int current = inputStream.read();
                if (current < 0) {
                    logger.warn("Did not receive any reply after sending {}", sendLog);
                    return false;
                } else {
                    if ((byte) current == ACK) {
                        logger.trace("Received ACK");
                        return true;
                    }
                    if ((byte) current == NACK) {
                        if (logInitialError) {
                            logger.warn("Received a NACK after sending {}", sendLog);
                        } else {
                            logger.trace("Received a NACK after writing data");
                        }
                        Thread.sleep(10);
                    } else {
                        if (logInitialError) {
                            if ((byte) current == 0) {
                                logger.warn("Received 0x00 and accepted as ACK");
                                return true;
                            }
                            logger.warn("Received unknown response {} after sending {}", String.format("%02X", current),
                                    sendLog);
                        } else {
                            logger.trace("Received unknown response {}", String.format("%02X", current));
                        }
                        Thread.sleep(2000);
                    }
                }
            }
            logger.warn("Failed 3 times to correctly send a frame");
        } catch (IOException e1) {
            logger.warn("Error reading from serial port: {}", e1.getMessage(), e1);
        } catch (InterruptedException e) {
            // ignore interruption
        }
        return false;
    }

    public @Nullable ByteBuffer receiveMsg() {
        try {
            ByteBuffer contens = ByteBuffer.allocate(1000);
            for (int retries = 0; retries < 10; retries++) {
                ByteBuffer readActual = ByteBuffer.allocate(1000);
                // Thread.sleep(100);
                for (int tries = 0; tries < 100; tries++) {
                    int current = inputStream.read();
                    if (current < 0) {
                        logger.warn("Unexpected end of input stream");
                        return null;
                    }
                    if ((byte) current == START) {
                        readActual.put((byte) current);
                        logger.trace("Received START of frame");
                        break;
                    }
                    logger.warn("Unexpected start of frame {}", String.format("%02X", current));
                }

                do {
                    // read data from serial device
                    while (inputStream.available() > 0) {
                        int current = inputStream.read();
                        if (current < 0) {
                            break;
                        }
                        readActual.put((byte) current);
                    }
                    // add wait states around reading the stream, so that interrupted transmissions are merged
                    Thread.sleep(20);
                    if (inputStream.available() > 0) {
                        continue;
                    }
                    Thread.sleep(80);
                } while (inputStream.available() > 0);
                readActual.limit(readActual.position());
                logger.trace("Received {}", bb2hex(readActual));
                readActual.rewind();
                if (readActual.get() != START) {
                    // we will never get here, code is just in case the way data is read is changed later
                    logger.warn("Did not receive \\xEE as the first byte of the frame {}", bb2hex(readActual));
                    return null;
                }
                readActual.get(); // IDENTITY
                byte ctrl = readActual.get();
                byte sequence = readActual.get();
                int length = readActual.getShort();
                int crcPos = readActual.position() + length;
                if (crcPos + 2 > readActual.limit()) {
                    // Below is changed to debug because I get this about every 13 minutes with 2 sec polling on
                    // 83334-3I. I did not have that issue with 83331-3i and same IR Probe.
                    logger.debug("Specified length {} longer than received data {}", length, bb2hex(readActual));
                    logger.trace("Sending NACK");
                    outputStream.write(NACK);
                    continue;
                }
                readActual.order(ByteOrder.LITTLE_ENDIAN);
                int messageCrc = readActual.getChar(crcPos);
                int calculatedCrc = crc16Calc.calculate(readActual.array(), crcPos, 0xFFFF) ^ 0xFFFF;
                if (messageCrc != calculatedCrc) {
                    logger.warn("incorrect CRC received. Message was {} calculated {}", bb2hex(readActual),
                            calculatedCrc);
                    logger.trace("Sending NACK");
                    outputStream.write(NACK);
                    continue;
                }
                boolean multipacket = (ctrl & 0x80) != 0;
                boolean firstInMultipacket = (ctrl & 0x40) != 0;
                boolean receiveToggleBit = (ctrl & 0x20) != 0;
                logger.trace("Sending ACK");
                outputStream.write(ACK);
                readActual.limit(readActual.limit() - 2);
                contens.put(readActual);
                if (!multipacket || sequence == 0) {
                    contens.limit(contens.position());
                    contens.position(0);
                    ByteBuffer ret = ByteBuffer.allocate(contens.limit());
                    ret.put(contens);
                    ret.position(0);
                    return ret;
                }
                // readActual is thrown away here.
            }
        } catch (IOException e1) {
            logger.warn("Error reading from serial port: {}", e1.getMessage(), e1);
        } catch (InterruptedException e) {
        }
        return null;
    }

    public @Nullable ByteBuffer receiveMsgAndCheckAck() {
        ByteBuffer readActual = receiveMsg();
        if (readActual == null) {
            return null;
        }

        C1218_ResponceCodes responceCode = C1218_ResponceCodes.values()[readActual.get()];
        if (responceCode != C1218_ResponceCodes.Acknowledge) {
            logger.warn("Unexpeced responce code {}", responceCode);
            return null;
        }
        return readActual;
    }

    public boolean handleTable0Reply(ByteBuffer tableData) {
        int tableLength = tableData.getShort();
        byte current = tableData.get();
        byteOrder = (current & 0x01) != 0 ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        int charFormat = (current >> 1) & 0x07;
        current = tableData.get();
        int timeFormat = current & 0x07;
        int dataAccessMethod = (current >> 3) & 0x03;
        boolean identificationFormatBCD = ((current >> 4) & 0x01) != 0;
        current = tableData.get(); // two Non-integer Formats
        String manufacturer = "";
        for (int n = 0; n < 4; n++)
            manufacturer += (char) tableData.get();
        int nameplateType = tableData.get() & 0xFF;
        int defaultSetUsed = tableData.get() & 0xFF;
        int procedureParameterLength = (byte) tableData.get() & 0xFF;
        int responseDataLength = tableData.get() & 0xFF;
        int standardVersion = tableData.get() & 0xFF;
        int standardRevision = tableData.get() & 0xFF;
        tableData.order(byteOrder);
        logger.info(
                "tableLength {} byteOrder {} charFormat {} timeFormat {} dataAccessMethod {} identificationFormatBCD {} manufacturer {} nameplateType {} defaultSetUsed {} procedureParameterLength {} responseDataLength {} standardVersion {} standardRevision {}",
                tableLength, byteOrder, charFormat, timeFormat, dataAccessMethod, identificationFormatBCD, manufacturer,
                nameplateType, defaultSetUsed, procedureParameterLength, responseDataLength, standardVersion,
                standardRevision);

        return true;
    }

    public boolean handleTable23Reply(ByteBuffer tableData) {
        int tableLength = tableData.getShort();
        tableData.order(byteOrder);
        updateState(CHANNEL_Fwd_active_energy, new QuantityType<>(tableData.getInt() / 1000.0, Units.KILOWATT_HOUR));
        updateState(CHANNEL_Rev_active_energy, new QuantityType<>(tableData.getInt() / 1000.0, Units.KILOWATT_HOUR));
        tableData.position(3);
        logger.debug("Fwd Active {} Wh Rev Active {} Wh", tableData.getInt(), tableData.getInt());
        return true;
    }

    public boolean handleTable28Reply(ByteBuffer tableData) {
        if (tableData.limit() != 44) {
            logger.warn("Table28 has unexpected length {} in message {}", tableData.limit(), bb2hex(tableData));
            return false;
        }
        int tableLength = tableData.getShort();
        if (tableLength != 0x28) {
            logger.warn("Table28 has unexpected table length {} in message {}", tableLength, bb2hex(tableData));
            return false;
        }
        tableData.order(byteOrder);
        logger.debug(
                "Fwd {} W Rev {} W Import Reactive {} VAr Export Reactive {} VAr Values L1 {} mA L2 {} mA L3 {} mA L1 {} mV L2 {} mV L3 {} mV",
                tableData.getInt(), tableData.getInt(), tableData.getInt(), tableData.getInt(), tableData.getInt(),
                tableData.getInt(), tableData.getInt(), tableData.getInt(), tableData.getInt(), tableData.getInt());
        tableData.position(3);
        updateState(CHANNEL_Fwd_active_power, new QuantityType<>(tableData.getInt(), Units.WATT));
        updateState(CHANNEL_Rev_active_power, new QuantityType<>(tableData.getInt(), Units.WATT));
        updateState(CHANNEL_Import_Reactive_VAr, new QuantityType<>(tableData.getInt(), Units.VAR));
        updateState(CHANNEL_Export_Reactive_VAr, new QuantityType<>(tableData.getInt(), Units.VAR));
        updateState(CHANNEL_L1_current, new QuantityType<>(tableData.getInt() / 1000.0, Units.AMPERE));
        updateState(CHANNEL_L2_current, new QuantityType<>(tableData.getInt() / 1000.0, Units.AMPERE));
        updateState(CHANNEL_L3_current, new QuantityType<>(tableData.getInt() / 1000.0, Units.AMPERE));
        updateState(CHANNEL_L1_voltage, new QuantityType<>(tableData.getInt() / 1000.0, Units.VOLT));
        updateState(CHANNEL_L2_voltage, new QuantityType<>(tableData.getInt() / 1000.0, Units.VOLT));
        updateState(CHANNEL_L3_voltage, new QuantityType<>(tableData.getInt() / 1000.0, Units.VOLT));
        return true;
    }

    public void TerminateSession() {
        if (sendRequestID(RequestID_Logoff)) {
            logger.debug("Logoff successfully");
        }
        if (sendRequestID(RequestID_Terminate)) {
            logger.debug("Session successfully terminated");
        }
    }

    public boolean isIdlePeriod(LocalTime time) {
        LocalTime startTime = LocalTime.parse(config.idleStartTime);
        LocalTime endTime = startTime.plusSeconds(config.idleSeconds);
        if (startTime.compareTo(endTime) <= 0)
            return time.compareTo(startTime) >= 0 && time.compareTo(endTime) < 0;
        return !(time.compareTo(endTime) >= 0 && time.compareTo(startTime) < 0);
    }

    public void pollStatus() {
        if (connectState == ConnectState.Init) {
            if (isIdlePeriod(LocalDateTime.now().toLocalTime())) {
                return;
            }
            toggleControl = false;

            // This did not fix initial NACK that is received when first RequestID_Ident is send
            // logger.trace("Sending wakeup 0x55");
            // try {
            // outputStream.write(new byte[] { (byte) 0x55 });
            // Thread.sleep(50);
            // } catch (IOException e1) {
            // updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR,
            // "Error writing to serial port");
            // } catch (InterruptedException e) {
            // return;
            // }

            logger.debug("Sending Ident");
            if (!sendRequestID(RequestID_Ident)) {
                updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR,
                        "Failed to send or receive Ident");
                TerminateSession();
                return;
            }
            if (!sendNegotiateRequest()) {
                updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR,
                        "Failed to send or receive Negotiate Request");
                return;
            }
            logger.debug("Negotiate successfully");
            if (!sendLogonRequest((short) config.userId, config.username)) {
                updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR,
                        "Failed to send or receive Logon Request");
                return;
            }
            lastLogonTime = System.currentTimeMillis();
            if (!sendSecurityRequest(config.password)) {
                updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR,
                        "Failed to send or receive Security Request");
                return;
            }
            final ByteBuffer table0 = sendReadTable(0);
            if (table0 == null) {
                updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.OFFLINE.COMMUNICATION_ERROR,
                        "Failed to send or receive Table 0 read");
                return;
            }

            updateStatus(ThingStatus.ONLINE);
            connectState = ConnectState.Connected;
        }

        boolean successfullyRead = false;

        ByteBuffer readActual = sendReadPartialTable(28, 0, 40);
        if (readActual != null) {
            if (handleTable28Reply(readActual)) {
                readActual = sendReadPartialTable(23, 0, 8);
                if (readActual != null) {
                    if (handleTable23Reply(readActual)) {
                        successfullyRead = true;
                    }
                }
            }
        }

        if (System.currentTimeMillis() - lastLogonTime + (config.refreshInterval * 1000) > config.logoffInterval
                * 1000) {
            TerminateSession();
            connectState = ConnectState.Init;
            return;
        }
        if (successfullyRead)
            return;
        connectState = ConnectState.Init;
        updateStatus(ThingStatus.OFFLINE);
    }
}
