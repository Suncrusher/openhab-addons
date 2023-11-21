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

import static org.eclipse.jdt.annotation.Checks.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.openhab.binding.smartmeterosgp.internal.SmartMeterOSGPBindingConstants.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.time.LocalTime;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openhab.core.config.core.Configuration;
import org.openhab.core.io.transport.serial.SerialPortEvent;
import org.openhab.core.io.transport.serial.SerialPortManager;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.binding.ThingHandlerCallback;

/**
 * The {@link SmartMeterOSGPHandler} is responsible for handling commands, which are
 * This class is used to test the binding .
 *
 * @author Kennet Nielsen - Initial contribution
 */
@NonNullByDefault
@ExtendWith(MockitoExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_METHOD)
public class SmartMeterOSGPHandlerTest {
    private Thing thingMock = mock(Thing.class);
    private ThingHandlerCallback callbackMock = mock(ThingHandlerCallback.class);
    private SerialPortEvent eventMock = mock(SerialPortEvent.class);
    private ByteArrayOutputStream outputStream = new ByteArrayOutputStream(1000);
    @Nullable
    private Configuration configuration = mock(Configuration.class);
    private SmartMeterOSGPConfiguration cfg = new SmartMeterOSGPConfiguration();

    @BeforeEach
    public void setUp() {
        when(thingMock.getConfiguration()).thenReturn(requireNonNull(configuration));
        when(configuration.as(SmartMeterOSGPConfiguration.class)).thenReturn(cfg);
    }

    @Test
    void testCrcCalc() throws InterruptedException, IOException {
        CRC16 crc16Calc = new CRC16(CRC16.Polynom.CRC16_CCIT);
        byte[] cmdReadTable23 = { (byte) 0xee, 0x00, 0x20, 0x00, 0x00, 0x08, 0x3f, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00,
                0x08 };
        int crc = crc16Calc.calculate(cmdReadTable23, 0xFFFF);
        assertEquals(0xf203, crc ^ 0xFFFF);
    }

    @Test
    void testSendSecurityRequest() throws InterruptedException, IOException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(mock(Thing.class), mock(SerialPortManager.class));
        uut.inputStream = new ByteArrayInputStream(new byte[] { ACK });
        uut.outputStream = outputStream;
        uut.sendSecurityRequest("0123456789abcdefghij");

        assertArrayEquals(
                new byte[] { START, IDENTITY, 0x00, 0x00, 0x00, 21, RequestID_Security, '0', '1', '2', '3', '4', '5',
                        '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', -128, 109 },
                outputStream.toByteArray());
    }

    @Test
    void testSendReadPartialTable() throws InterruptedException, IOException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(mock(Thing.class), mock(SerialPortManager.class));
        uut.inputStream = new ByteArrayInputStream(new byte[] { ACK });
        uut.outputStream = outputStream;
        uut.sendReadPartialTable(28, 0x010203, (short) 8);

        assertArrayEquals(new byte[] { START, IDENTITY, 0x00, 0x00, 0x00, 8, RequestID_ReadPartial, 0, 28, 1, 2, 3, 0,
                8, -64, 41 }, outputStream.toByteArray());
    }

    @Test
    void testSendNegotiateRequest() throws InterruptedException, IOException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(mock(Thing.class), mock(SerialPortManager.class));
        uut.inputStream = mock(InputStream.class);
        uut.outputStream = outputStream;
        when(uut.inputStream.read()).thenReturn((int) ACK).thenReturn(-1);
        uut.sendNegotiateRequest();
        assertArrayEquals(new byte[] { START, IDENTITY, 0x00, 0x00, 0x00, 0x05, RequestID_Negotiate2, 0x00, 0x40, 0x02,
                0x06, 29, 21 }, outputStream.toByteArray());
    }

    @Test
    void testSendLogonRequest() throws InterruptedException, IOException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(mock(Thing.class), mock(SerialPortManager.class));
        uut.inputStream = mock(InputStream.class);
        uut.outputStream = outputStream;
        when(uut.inputStream.read()).thenReturn((int) ACK).thenReturn(-1);
        uut.sendLogonRequest((short) 1, "0000");
        assertArrayEquals(new byte[] { START, IDENTITY, 0x00, 0x00, 0x00, 13, RequestID_Logon, 0x00, 0x01, 0x30, 0x30,
                0x30, 0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, -25, 96 }, outputStream.toByteArray());
    }

    @Test
    void testThatCrcErrorReturnNACK() throws InterruptedException, IOException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(thingMock, mock(SerialPortManager.class));
        byte[] identRequestReply = { (byte) 0xee, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x02, 0x00, 0x00,
                (byte) 0xa2, 0x00 }; // Last 0x00 should be 0x5a
        uut.inputStream = new ByteArrayInputStream(identRequestReply);
        uut.outputStream = outputStream;
        uut.receiveMsg();
        assertArrayEquals(new byte[] { NACK }, outputStream.toByteArray());
    }

    @Test
    void testReceiveMsgWithFirstExtraBytes() throws InterruptedException, IOException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(thingMock, mock(SerialPortManager.class));
        byte[] terminateReply = { (byte) 0xFF, (byte) 0xee, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x11, 0x31 }; // 0xFF is
                                                                                                              // extra
        uut.inputStream = new ByteArrayInputStream(terminateReply);
        uut.outputStream = outputStream;
        ByteBuffer msg = uut.receiveMsgAndCheckAck();
        assertArrayEquals(new byte[] { ACK }, outputStream.toByteArray());
        assertArrayEquals(new byte[] { 0x00 }, msg.array());
    }

    @Test
    void testReceiveMsgWithExtraBytes() throws InterruptedException, IOException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(thingMock, mock(SerialPortManager.class));
        byte[] terminateReply = { (byte) 0xee, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x11, 0x31, ACK }; // ACK is extra
        uut.inputStream = new ByteArrayInputStream(terminateReply);
        uut.outputStream = outputStream;
        ByteBuffer msg = uut.receiveMsg();
        assertArrayEquals(new byte[] { ACK }, outputStream.toByteArray());
    }

    @Test
    void testReceiveMsgWith1MissingByte() throws InterruptedException, IOException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(thingMock, mock(SerialPortManager.class));
        byte[] terminateReply = { (byte) 0xee, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x11 }; // Missing 0x31
        uut.inputStream = new ByteArrayInputStream(terminateReply);
        uut.outputStream = outputStream;
        assertNull(uut.receiveMsg());
    }

    @Test
    void testOfflineBeforeStartOfDefaultRange() throws InterruptedException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(thingMock, mock(SerialPortManager.class));
        uut.initialize();
        assertFalse(uut.isIdlePeriod(LocalTime.parse("02:09:59.999")));
    }

    @Test
    void testOfflineInStartOfDefaultRange() throws InterruptedException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(thingMock, mock(SerialPortManager.class));
        uut.initialize();
        assertTrue(uut.isIdlePeriod(LocalTime.parse("02:10:00.000")));
    }

    @Test
    void testOfflineAtEndOfDefaultRange() throws InterruptedException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(thingMock, mock(SerialPortManager.class));
        uut.initialize();
        assertTrue(uut.isIdlePeriod(LocalTime.parse("02:17:59.999")));
    }

    @Test
    void testOfflineAfterDefaultRange() throws InterruptedException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(thingMock, mock(SerialPortManager.class));
        uut.initialize();
        assertFalse(uut.isIdlePeriod(LocalTime.parse("02:18:00.000")));
    }

    @Test
    void testIdlePeriodOverMidNight() throws InterruptedException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(thingMock, mock(SerialPortManager.class));
        cfg.idleStartTime = "23:59:00";
        uut.initialize();
        assertFalse(uut.isIdlePeriod(LocalTime.parse("23:58:59.999")));
        assertTrue(uut.isIdlePeriod(LocalTime.parse("23:59:00.000")));
        assertTrue(uut.isIdlePeriod(LocalTime.parse("00:06:59.999")));
        assertFalse(uut.isIdlePeriod(LocalTime.parse("00:07:00.000")));
    }

    @Test
    void testIdlePeriod0isOnline() throws InterruptedException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(thingMock, mock(SerialPortManager.class));
        cfg.idleSeconds = 0;
        uut.initialize();
        assertFalse(uut.isIdlePeriod(LocalTime.parse("02:10:00.000")));
    }
}
