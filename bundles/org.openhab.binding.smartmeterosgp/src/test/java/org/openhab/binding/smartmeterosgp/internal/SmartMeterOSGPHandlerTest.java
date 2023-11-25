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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
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
import org.openhab.core.library.types.QuantityType;
import org.openhab.core.library.unit.Units;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingUID;
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
    void testHandleTable0Reply() throws InterruptedException, IOException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(thingMock, mock(SerialPortManager.class));
        // when(uut.inputStream.read()).thenReturn(0xEE,0,0x20,0,0,0x01,0,0x80,0x51);
        // when(uut.inputStream.available()).thenReturn(8,7,6,5,4,3,2,1,0,0);
        uut.inputStream = mock(InputStream.class);
        uut.outputStream = outputStream;
        when(uut.inputStream.read()).thenReturn(0xEE, 0x00, 0xC0, 0x01, 0x00, 0x38, 0x00, 0x00, 0x4F, 0x02, 0x2A, 0x88,
                0x45, 0x4C, 0x4F, 0x4E, 0x02, 0x00, 0xFF, 0x0C, 0x01, 0x00, 0x0A, 0x0D, 0x02, 0x0C, 0x09, 0x04, 0xFF,
                0xB5, 0xF1, 0x5F, 0x02, 0x1D, 0xF4, 0xF0, 0xCF, 0x07, 0xFF, 0xFF, 0xFF, 0xF8, 0xFF, 0xFF, 0xFF, 0x7F,
                0xFC, 0xEF, 0x03, 0x04, 0x02, 0x70, 0xF4, 0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0xFE, 0x7B, 0x1F, 0x00, 0x8A,
                0xB5).thenReturn(0xee, 0x00, 0xa0, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0xe6, 0x80, 0x80, 0x01, 0x02,
                        0x04, 0x60, 0x00, 0x00, 0x02, 0xff, 0xe6, 0xc6, 0x38, 0x0e, 0x89, 0xbc, 0x73, 0xb8, 0x63, 0x01,
                        0x02, 0x02, 0xcd, 0x37, 0x82, -1);
        when(uut.inputStream.available()).thenReturn(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 0, 0, 0).thenReturn(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0);

        ByteBuffer buf = uut.receiveMsgAndCheckAck();
        assertNotNull(buf);
        assertArrayEquals(
                new byte[] { 0x00, 0x00, 0x4F, 0x02, 0x2A, (byte) 0x88, 0x45, 0x4C, 0x4F, 0x4E, 0x02, 0x00, (byte) 0xFF,
                        0x0C, 0x01, 0x00, 0x0A, 0x0D, 0x02, 0x0C, 0x09, 0x04, (byte) 0xFF, (byte) 0xB5, (byte) 0xF1,
                        0x5F, 0x02, 0x1D, (byte) 0xF4, (byte) 0xF0, (byte) 0xCF, 0x07, (byte) 0xFF, (byte) 0xFF,
                        (byte) 0xFF, (byte) 0xF8, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x7F, (byte) 0xFC, (byte) 0xEF,
                        0x03, 0x04, 0x02, 0x70, (byte) 0xF4, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                        (byte) 0xBF, (byte) 0xFE, 0x7B, 0x1F, 0x00, 0x00, 0x00, 0x00, (byte) 0xe6, (byte) 0x80,
                        (byte) 0x80, 0x01, 0x02, 0x04, 0x60, 0x00, 0x00, 0x02, (byte) 0xff, (byte) 0xe6, (byte) 0xc6,
                        0x38, 0x0e, (byte) 0x89, (byte) 0xbc, 0x73, (byte) 0xb8, 0x63, 0x01, 0x02, 0x02, (byte) 0xcd },
                buf.array());

        uut.setCallback(callbackMock);
        if (buf != null)
            uut.handleTable0Reply(buf);

        // verify(callbackMock).statusUpdated(eq(thingMock),
        // eq(new ThingStatusInfo(ThingStatus.ONLINE, ThingStatusDetail.NONE, null)));
    }

    @Test
    void testHandleTable28Reply() throws InterruptedException, IOException {
        SmartMeterOSGPHandler uut = new SmartMeterOSGPHandler(thingMock, mock(SerialPortManager.class));
        byte[] readTable28Reply = { (byte) 0xEE, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x28, (byte) 0xEF, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x02, 0x00,
                0x00, (byte) 0xBA, 0x01, 0x00, 0x00, 0x38, 0x01, 0x00, 0x00, 0x67, (byte) 0x94, 0x03, 0x00, 0x6E,
                (byte) 0x96, 0x03, 0x00, (byte) 0xC2, (byte) 0x9A, 0x03, 0x00, 0x2F, (byte) 0x96, (byte) 0xC3 };
        when(thingMock.getUID()).thenReturn(new ThingUID("te:s:t"));
        uut.inputStream = new ByteArrayInputStream(readTable28Reply);
        uut.outputStream = outputStream;
        ByteBuffer buf = uut.receiveMsgAndCheckAck();
        assertNotNull(buf);
        uut.setCallback(callbackMock);
        if (buf != null)
            uut.handleTable28Reply(buf);

        assertArrayEquals(new byte[] { ACK }, outputStream.toByteArray());

        verify(callbackMock).stateUpdated(eq(new ChannelUID("te:s:t:" + CHANNEL_Fwd_active_power)),
                eq(new QuantityType<>(239, Units.WATT)));

        verify(callbackMock).stateUpdated(eq(new ChannelUID("te:s:t:" + CHANNEL_Rev_active_power)),
                eq(new QuantityType<>(0, Units.WATT)));
        verify(callbackMock).stateUpdated(eq(new ChannelUID("te:s:t:" + CHANNEL_Import_Reactive_VAr)),
                eq(new QuantityType<>(0x14, Units.VAR)));
        verify(callbackMock).stateUpdated(eq(new ChannelUID("te:s:t:" + CHANNEL_Export_Reactive_VAr)),
                eq(new QuantityType<>(0, Units.VAR)));
        verify(callbackMock).stateUpdated(eq(new ChannelUID("te:s:t:" + CHANNEL_L1_current)),
                eq(new QuantityType<>(0.628, Units.AMPERE)));
        verify(callbackMock).stateUpdated(eq(new ChannelUID("te:s:t:" + CHANNEL_L2_current)),
                eq(new QuantityType<>(0.442, Units.AMPERE)));
        verify(callbackMock).stateUpdated(eq(new ChannelUID("te:s:t:" + CHANNEL_L3_current)),
                eq(new QuantityType<>(0.312, Units.AMPERE)));
        verify(callbackMock).stateUpdated(eq(new ChannelUID("te:s:t:" + CHANNEL_L1_voltage)),
                eq(new QuantityType<>(234.599, Units.VOLT)));
        verify(callbackMock).stateUpdated(eq(new ChannelUID("te:s:t:" + CHANNEL_L2_voltage)),
                eq(new QuantityType<>(235.118, Units.VOLT)));
        verify(callbackMock).stateUpdated(eq(new ChannelUID("te:s:t:" + CHANNEL_L3_voltage)),
                eq(new QuantityType<>(236.226, Units.VOLT)));
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
