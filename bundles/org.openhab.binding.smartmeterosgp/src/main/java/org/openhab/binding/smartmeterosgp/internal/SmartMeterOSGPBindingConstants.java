/**
 * Copyright (c) 2010-2022 Contributors to the openHAB project
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

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.thing.ThingTypeUID;

/**
 * The {@link SmartMeterOSGPBindingConstants} class defines common constants, which are
 * used across the whole binding.
 *
 * @author Kennet Nielsen - Initial contribution
 */
@NonNullByDefault
public class SmartMeterOSGPBindingConstants {

    private static final String BINDING_ID = "smartmeterosgp";

    // List of all Thing Type UIDs
    public static final ThingTypeUID THING_TYPE_SAMPLE = new ThingTypeUID(BINDING_ID, "sample");

    // List of all Channel ids
    public static final String CHANNEL_Fwd_active_power = "Fwd_active_power";
    public static final String CHANNEL_Rev_active_power = "Rev_active_power";
    public static final String CHANNEL_Import_Reactive_VAr = "Import_Reactive_VAr";
    public static final String CHANNEL_Export_Reactive_VAr = "Export_Reactive_VAr";
    public static final String CHANNEL_L1_current = "L1_current";
    public static final String CHANNEL_L2_current = "L2_current";
    public static final String CHANNEL_L3_current = "L3_current";
    public static final String CHANNEL_L1_voltage = "L1_voltage";
    public static final String CHANNEL_L2_voltage = "L2_voltage";
    public static final String CHANNEL_L3_voltage = "L3_voltage";

    // C12.18 protocol constants
    public static final byte NACK = 0x15;
    public static final byte ACK = 0x06;
    public static final byte START = (byte) 0xEE;
    public static final byte IDENTITY = 0;

    public static final byte RequestID_Ident = 0x20;
    public static final byte RequestID_Terminate = 0x21;
    public static final byte RequestID_Read = 0x30;
    public static final byte RequestID_ReadPartial = 0x3f;
    public static final byte RequestID_Write = 0x40;
    public static final byte RequestID_WritePartial = 0x4f;
    public static final byte RequestID_Logon = 0x50;
    public static final byte RequestID_Security = 0x51;
    public static final byte RequestID_Logoff = 0x52;
    public static final byte RequestID_Negotiate = 0x60;
    public static final byte RequestID_Negotiate2 = 0x61;
    public static final byte RequestID_Wait = 0x70;

    public enum C1218_ResponceCodes {
        Acknowledge, // 0: 'ok (Acknowledge)',
        Error, // 1: 'err (Error)',
        Service_Not_Supported, // 2: 'sns (Service Not Supported)',
        Insufficient_Security_Clearance, // 3: 'isc (Insufficient Security Clearance)',
        Operation_Not_Possible, // 4: 'onp (Operation Not Possible)',
        Inappropriate_Action_Requested, // 5: 'iar (Inappropriate Action Requested)',
        Device_Busy, // 6: 'bsy (Device Busy)',
        Data_Not_Ready, // 7: 'dnr (Data Not Ready)',
        Data_Locked, // 8: 'dlk (Data Locked)',
        Renegotiate_Request, // 9: 'rno (Renegotiate Request)',
        Invalid_Service_Sequence_State // 10: 'isss (Invalid Service Sequence State)',
    };
}
