
// Copyright 2013 Stephen Vickers <stephen.vickers.sv@gmail.com>

import { Ber as ber, type Writer, type Reader } from "asn1-ber";
import { SmartBuffer } from "smart-buffer";
import { createSocket, type SocketType, type Socket as DgramSocket } from "node:dgram";
import { Socket } from "node:net";
import { EventEmitter } from "node:events";
import { createHash, createHmac, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import mibparser from "./lib/mib.js";
let DEBUG = false;

const MIN_SIGNED_INT32 = -2147483648;
const MAX_SIGNED_INT32 = 2147483647;
const MIN_UNSIGNED_INT32 = 0;
const MAX_UNSIGNED_INT32 = 4294967295;

function debug (line: any): void {
	if ( DEBUG ) {
		console.debug (line);
	}
}

type Values<T> = T[keyof T]

/*****************************************************************************
 ** Constants
 **/

export type OID = {
    str: string;
    len: number;
    idx: number;
}

export type VarbindValue = boolean | string | null | number | Buffer
export type VarbindType = typeof ObjectType[keyof typeof ObjectType] & number
export type Varbind = {
    type?: VarbindType | null;
    oid: OID | null | string;
    value?: VarbindValue;
}

type ToNumber<S> = S extends `${infer N extends number}` ? N : S;

function _expandConstantObject<
    T extends {[k in number | string]: S},
    S extends string
>(
    obj: T
): {[K in keyof T as T[K]]: ToNumber<K>} & {[K in keyof T]: T[K]} {
    const res = {} as any;
    Object.entries(obj).forEach(([key, value]) => {
        res[value] = parseInt(key);
    });
    return res;
}

function _as<
    T extends {[k in number | string]: S},
    S extends string | number
>(obj: T): T {
    return obj
}

export const ErrorStatus = {
    ..._expandConstantObject({
        0: "NoError",
        1: "TooBig",
        2: "NoSuchName",
        3: "BadValue",
        4: "ReadOnly",
        5: "GeneralError",
        6: "NoAccess",
        7: "WrongType",
        8: "WrongLength",
        9: "WrongEncoding",
        10: "WrongValue",
        11: "NoCreation",
        12: "InconsistentValue",
        13: "ResourceUnavailable",
        14: "CommitFailed",
        15: "UndoFailed",
        16: "AuthorizationError",
        17: "NotWritable",
        18: "InconsistentName"
    })
};

type ErrorStatusKey = number & keyof typeof ErrorStatus;

const _ObjectType = {
    ... _expandConstantObject({
        1: "Boolean",
        2: "Integer",
        3: "BitString",
        4: "OctetString",
        5: "Null",
        6: "OID",
        64: "IpAddress",
        65: "Counter",
        66: "Gauge",
        67: "TimeTicks",
        68: "Opaque",
        70: "Counter64",
        128: "NoSuchObject",
        129: "NoSuchInstance",
        130: "EndOfMibView"
    })
};
export const ObjectType = {
    ..._ObjectType,
    // ASN.1
    "INTEGER": _ObjectType.Integer,
    "OCTET STRING": _ObjectType.OctetString,
    "OBJECT IDENTIFIER": _ObjectType.OID,
    // SNMPv2-SMI
    "Integer32": _ObjectType.Integer,
    "Counter32": _ObjectType.Counter,
    "Gauge32": _ObjectType.Gauge,
    "Unsigned32": _ObjectType.Gauge
};

export const PduType = {
    ..._expandConstantObject({
        160: "GetRequest",
        161: "GetNextRequest",
        162: "GetResponse",
        163: "SetRequest",
        164: "Trap",
        165: "GetBulkRequest",
        166: "InformRequest",
        167: "TrapV2",
        168: "Report"
    })
};

type PduTypeKey = keyof typeof PduType;

export const TrapType = {
    ..._expandConstantObject({
        0: "ColdStart",
        1: "WarmStart",
        2: "LinkDown",
        3: "LinkUp",
        4: "AuthenticationFailure",
        5: "EgpNeighborLoss",
        6: "EnterpriseSpecific"
    })
};

export const SecurityLevel = {
    ..._expandConstantObject({
        1: "noAuthNoPriv",
        2: "authNoPriv",
        3: "authPriv"
    })
};

export const AuthProtocols = {
    ..._expandConstantObject({
        "1": "none",
        "2": "md5",
        "3": "sha",
        "4": "sha224",
        "5": "sha256",
        "6": "sha384",
        "7": "sha512"
    })
};

export const PrivProtocols = {
    ..._expandConstantObject({
        "1": "none",
        "2": "des",
        "4": "aes",
        "6": "aes256b",
        "8": "aes256r"
    })
};

const UsmStatsBase = "1.3.6.1.6.3.15.1.1";

const UsmStats = {
    ..._expandConstantObject({
        "1": "Unsupported Security Level",
        "2": "Not In Time Window",
        "3": "Unknown User Name",
        "4": "Unknown Engine ID",
        "5": "Wrong Digest (incorrect password, community or key)",
        "6": "Decryption Error"
    })
};

export const MibProviderType = {
    ..._expandConstantObject({
        "1": "Scalar",
        "2": "Table"
    })
};

export const Version1 = 0;
export const Version2c = 1;
export const Version3 = 3;

export const Version = _as({
	"1": Version1,
	"2c": Version2c,
	"3": Version3
});

type SecurityModel = typeof Version1 | typeof Version2c | typeof Version3;

export const AgentXPduType = {
    ..._expandConstantObject({
        1: "Open",
        2: "Close",
        3: "Register",
        4: "Unregister",
        5: "Get",
        6: "GetNext",
        7: "GetBulk",
        8: "TestSet",
        9: "CommitSet",
        10: "UndoSet",
        11: "CleanupSet",
        12: "Notify",
        13: "Ping",
        14: "IndexAllocate",
        15: "IndexDeallocate",
        16: "AddAgentCaps",
        17: "RemoveAgentCaps",
        18: "Response"
    })
};

export const AccessControlModelType = {
    ..._expandConstantObject({
        0: "None",
        1: "Simple"
    })
};

export const AccessLevel = {
    ..._expandConstantObject({
        0: "None",
        1: "ReadOnly",
        2: "ReadWrite"
    })
};
type AccessLevelType = keyof typeof AccessLevel

// SMIv2 MAX-ACCESS values
export const MaxAccess = {
    ..._expandConstantObject({
        0: "not-accessible",
        1: "accessible-for-notify",
        2: "read-only",
        3: "read-write",
        4: "read-create"
    })
};

// SMIv1 ACCESS value mapping to SMIv2 MAX-ACCESS
const AccessToMaxAccess = _as({
	"not-accessible": "not-accessible",
	"read-only": "read-only",
	"read-write": "read-write",
	"write-only": "read-write"
});

export const RowStatus = {
    ..._expandConstantObject({
        // status values
        1: "active",
        2: "notInService",
        3: "notReady",

        // actions
        4: "createAndGo",
        5: "createAndWait",
        6: "destroy"
    })
};

export const ResponseInvalidCode = {
    ..._expandConstantObject({
        1: "EIp4AddressSize",
        2: "EUnknownObjectType",
        3: "EUnknownPduType",
        4: "ECouldNotDecrypt",
        5: "EAuthFailure",
        6: "EReqResOidNoMatch",
        // 7: "ENonRepeaterCountMismatch",  // no longer used
        8: "EOutOfOrder",
        9: "EVersionNoMatch",
        10: "ECommunityNoMatch",
        11: "EUnexpectedReport",
        12: "EResponseNotHandled",
        13: "EUnexpectedResponse"
    })
};

export const OidFormat = _as({
	"oid": "oid",
	"path": "path",
	"module": "module"
});

/*****************************************************************************
 ** Exception class definitions
 **/

type ResponseInvalidErrorInfo = {
    user: ;
}

export class ResponseInvalidError
    extends Error
{
    readonly info: ResponseInvalidErrorInfo | undefined
    readonly code: number

    constructor(message: string, code: number, info?: ResponseInvalidErrorInfo) {
        super(message)
	    this.name = "ResponseInvalidError";
	    this.info = info;
	    this.code = code;
    }
}

export class RequestInvalidError
    extends Error
{
    constructor (message: string) {
        super(message)
	    this.name = "RequestInvalidError";
    }
}

export class RequestFailedError
    extends Error
{
    readonly status: ErrorStatusKey;

    constructor (message: string, status: ErrorStatusKey) {
        super(message)
	    this.name = "RequestFailedError";
	    this.status = status;
    }
}

export class RequestTimedOutError
    extends Error
{
    constructor (message: string) {
        super(message)
	    this.name = "RequestTimedOutError";
    }
}

class ProcessingError
    extends Error
{
    readonly error: Error;
    readonly rinfo: string;
    readonly buffer: string;

    constructor (message: string, error: Error, rinfo: string, buffer: string) {
        super(message)
	    this.name = "ProcessingError";
	    this.error = error;
	    this.rinfo = rinfo;
	    this.buffer = buffer;
    }
}

/*****************************************************************************
 ** OID and varbind helper functions
 **/

export function isVarbindError (varbind: Varbind): boolean {
	return !!(varbind.type == ObjectType.NoSuchObject
	|| varbind.type == ObjectType.NoSuchInstance
	|| varbind.type == ObjectType.EndOfMibView);
}

export function varbindError (varbind: Varbind): string {
	return (ObjectType[varbind.type!] ?? "NotAnError") + ": " + varbind.oid;
}

function oidFollowsOid (oidString: string, nextString: string): boolean {
	const oid = {str: oidString, len: oidString.length, idx: 0};
	const next = {str: nextString, len: nextString.length, idx: 0};
	const dotCharCode = ".".charCodeAt (0);

	function getNumber (item: typeof oid): number | null {
		let n = 0;
		if (item.idx >= item.len)
			return null;
		while (item.idx < item.len) {
			const charCode = item.str.charCodeAt (item.idx++);
			if (charCode == dotCharCode)
				return n;
			n = (n ? (n * 10) : n) + (charCode - 48);
		}
		return n;
	}

	while (1) {
		const oidNumber = getNumber (oid);
		const nextNumber = getNumber (next);

		if (oidNumber !== null) {
			if (nextNumber !== null) {
				if (nextNumber > oidNumber) {
					return true;
				} else if (nextNumber < oidNumber) {
					return false;
				}
			} else {
				return true;
			}
		} else {
			return true;
		}
	}
    return false
}

function oidInSubtree (oidString: string, nextString: string): boolean {
	const oid = oidString.split (".");
	const next = nextString.split (".");

	if (oid.length > next.length)
		return false;

	for (let i = 0; i < oid.length; i++) {
		if (next[i] != oid[i])
			return false;
	}

	return true;
}

function readInt32 (buffer: Reader): number {
	const parsedInt = buffer.readInt ();
	if ( ! Number.isInteger(parsedInt) ) {
		throw new TypeError('Value read as integer ' + parsedInt + ' is not an integer');
	}
	if ( parsedInt! < MIN_SIGNED_INT32 || parsedInt! > MAX_SIGNED_INT32 ) {
		throw new RangeError('Read integer ' + parsedInt + ' is outside the signed 32-bit range');
	}
	return parsedInt!;
}

function readUint32 (buffer: Reader): number {
	let parsedInt = buffer.readInt ();
	if ( ! Number.isInteger(parsedInt) ) {
		throw new TypeError('Value read as integer ' + parsedInt + ' is not an integer');
	}
	parsedInt = (parsedInt!>>>0);
	if ( parsedInt < MIN_UNSIGNED_INT32 || parsedInt > MAX_UNSIGNED_INT32 ) {
		throw new RangeError('Read integer ' + parsedInt + ' is outside the unsigned 32-bit range');
	}
	return parsedInt;
}

function readUint64 (buffer: Reader): Buffer {
	const value = buffer.readString (ObjectType.Counter64, true) as Buffer;

	return value;
}

function readIpAddress (buffer: Reader): string {
	const bytes = buffer.readString (ObjectType.IpAddress, true) as Buffer;
	if (bytes.length != 4)
		throw new ResponseInvalidError ("Length '" + bytes.length
				+ "' of IP address '" + bytes.toString ("hex")
				+ "' is not 4", ResponseInvalidCode.EIp4AddressSize);
	const value = bytes[0] + "." + bytes[1] + "." + bytes[2] + "." + bytes[3];
	return value;
}

function readVarbindValue (
    buffer: Reader,
    type: VarbindType
): VarbindValue {
    switch (type)
    {
	    case ObjectType.Boolean:
		    return buffer.readBoolean ();
	    case ObjectType.Integer:
		    return readInt32 (buffer);
	    case ObjectType.BitString:
		    return buffer.readBitString();
	    case ObjectType.OctetString:
		    return buffer.readString (null, true);
	    case ObjectType.Null:
		    buffer.readByte ();
		    buffer.readByte ();
		    return null;
	    case ObjectType.OID:
		    return buffer.readOID ();
	    case ObjectType.IpAddress:
		    return readIpAddress (buffer);
	    case ObjectType.Counter:
		    return readUint32 (buffer);
	    case ObjectType.Gauge:
		    return readUint32 (buffer);
	    case ObjectType.TimeTicks:
		    return readUint32 (buffer);
	    case ObjectType.Opaque:
		    return buffer.readString (ObjectType.Opaque, true);
	    case ObjectType.Counter64:
		    return readUint64 (buffer);
	    case ObjectType.NoSuchObject:
		    buffer.readByte ();
		    buffer.readByte ();
		    return null;
	    case ObjectType.NoSuchInstance:
            buffer.readByte ();
            buffer.readByte ();
            return null;
    	case ObjectType.EndOfMibView:
            buffer.readByte ();
            buffer.readByte ();
            return null;
    }
    throw new ResponseInvalidError ("Unknown type '" + type
        + "' in response", ResponseInvalidCode.EUnknownObjectType);
}

function readVarbinds (buffer: Reader, varbinds: Array<Varbind>): void {
	buffer.readSequence ();

	while (1) {
		buffer.readSequence ();
		if ( buffer.peek () != ObjectType.OID )
			break;
		const oid = buffer.readOID ();
		const type = buffer.peek ();

		if (type == null)
			break;

		const value = readVarbindValue (buffer, type as VarbindType);

		varbinds.push ({
			oid: oid,
			type: type as VarbindType,
			value: value
		});
	}
}

function writeInt32 (buffer: Writer, type: number, value: number): void {
	if ( ! Number.isInteger(value) ) {
		throw new TypeError('Value to write as integer ' + value + ' is not an integer');
	}
	if ( value < MIN_SIGNED_INT32 || value > MAX_SIGNED_INT32 ) {
		throw new RangeError('Integer to write ' + value + ' is outside the signed 32-bit range');
	}
	buffer.writeInt(value, type);
}

function writeUint32 (buffer: Writer, type: number, value: number): void {
	if ( ! Number.isInteger(value) ) {
		throw new TypeError('Value to write as integer ' + value + ' is not an integer');
	}
	if ( value < MIN_UNSIGNED_INT32 || value > MAX_UNSIGNED_INT32 ) {
		throw new RangeError('Integer to write ' + value + ' is outside the unsigned 32-bit range');
	}
	buffer.writeInt(value, type);
}

function writeUint64 (buffer: Writer, value: Buffer): void {
	buffer.writeBuffer (value, ObjectType.Counter64);
}

function writeVarbinds (buffer: Writer, varbinds: Array<Varbind>): void {
	buffer.startSequence ();
	for (const varbind of varbinds) {
		buffer.startSequence ();
		buffer.writeOID (varbind.oid as string);

		if (varbind.type && varbind.hasOwnProperty("value")) {
			const type = varbind.type;
			const value = varbind.value;

			switch ( type ) {
				case ObjectType.Boolean:
					buffer.writeBoolean (value ? true : false);
					break;
				case ObjectType.Integer: // also Integer32
					writeInt32 (buffer, ObjectType.Integer, value as number);
					break;
				case ObjectType.OctetString:
					if (typeof value == "string")
						buffer.writeString (value);
					else
						buffer.writeBuffer (value as Buffer, ObjectType.OctetString);
					break;
				case ObjectType.Null:
					buffer.writeNull ();
					break;
				case ObjectType.OID:
					buffer.writeOID (value as string);
					break;
				case ObjectType.IpAddress:
					const bytes = (value as string).split (".");
					if (bytes.length != 4)
						throw new RequestInvalidError ("Invalid IP address '"
								+ value + "'");
					buffer.writeBuffer (Buffer.from (bytes as any), 64);
					break;
				case ObjectType.Counter: // also Counter32
					writeUint32 (buffer, ObjectType.Counter, value as number);
					break;
				case ObjectType.Gauge: // also Gauge32 & Unsigned32
					writeUint32 (buffer, ObjectType.Gauge, value as number);
					break;
				case ObjectType.TimeTicks:
					writeUint32 (buffer, ObjectType.TimeTicks, value as number);
					break;
				case ObjectType.Opaque:
					buffer.writeBuffer (value as Buffer, ObjectType.Opaque);
					break;
				case ObjectType.Counter64:
					writeUint64 (buffer, value as Buffer);
					break;
				case ObjectType.NoSuchObject:
				case ObjectType.NoSuchInstance:
				case ObjectType.EndOfMibView:
					buffer.writeByte (type);
					buffer.writeByte (0);
					break;
				default:
					throw new RequestInvalidError ("Unknown type '" + type
						+ "' in request");
			}
		} else {
			buffer.writeNull ();
		}

		buffer.endSequence ();
	}
	buffer.endSequence ();
}

/*****************************************************************************
 ** PDU class definitions
 **/

type SimplePduOptions = {
    maxRepetitions?: number;
    nonRepeaters?: number;
    context?: string;
}

class SimplePdu
{
    id: number;
    type: number;
    protected options: SimplePduOptions;
    varbinds: Array<Varbind>;
    protected nonRepeaters: number;
    protected maxRepetitions: number;

    contextEngineID: Buffer | undefined;
    contextName: string;
    scoped: boolean;

    constructor (id?: number, varbinds?: Array<Varbind>, options?: SimplePduOptions) {
        this.id = id ?? 0;
        this.type = 0;
        this.options = options ?? {};
        this.varbinds = varbinds ?? [];
        this.maxRepetitions = options?.maxRepetitions ?? 0;
        this.nonRepeaters = options?.nonRepeaters ?? 0;

        this.contextEngineID = undefined;
        this.contextName = options?.context ?? "";
        this.scoped = false;
    }

    toBuffer (buffer: Writer): void {
        buffer.startSequence (this.type);

        writeInt32 (buffer, ObjectType.Integer, this.id);
        writeInt32 (buffer, ObjectType.Integer,
                (this.type == PduType.GetBulkRequest)
                ? (this.options.nonRepeaters ?? 0)
                : 0);
        writeInt32 (buffer, ObjectType.Integer,
                (this.type == PduType.GetBulkRequest)
                ? (this.options.maxRepetitions ?? 0)
                : 0);

        writeVarbinds (buffer, this.varbinds);

        buffer.endSequence ();
    }

    initializeFromVariables (id: number, varbinds: Array<Varbind>, options?: SimplePduOptions): void {
        this.id = id;
        this.varbinds = varbinds;
        this.options = options ?? {};
        this.contextName = (options && options.context) ? options.context : "";
    }

    initializeFromBuffer (reader: Reader): void {
        this.type = reader.peek ()!;
        reader.readSequence ();

        this.id = readInt32 (reader);
        this.nonRepeaters = readInt32 (reader)!;
        this.maxRepetitions = readInt32 (reader)!;

        this.varbinds = [];
        readVarbinds (reader, this.varbinds);
    }

    getResponsePduForRequest (): GetResponsePdu {
	    const responsePdu = GetResponsePdu.createFromVariables(this.id, [], {});
        if ( this.contextEngineID ) {
            responsePdu.contextEngineID = this.contextEngineID;
            responsePdu.contextName = this.contextName;
        }
        return responsePdu;
    }

    static createFromVariables<T extends SimplePdu> (pduClass: new(id?: number, varbinds?: Array<Varbind>, options?: SimplePduOptions) => T, id: number, varbinds: Array<Varbind>, options?: SimplePduOptions): T {
	   const pdu = new pduClass (id, varbinds, options);
	   pdu.id = id;
	   pdu.varbinds = varbinds;
	   pdu.options = options ?? {};
	   pdu.contextName = (options && options.context) ? options.context : "";
	   return pdu;
    }
}

class GetBulkRequestPdu
    extends SimplePdu
{
    constructor(id?: number, varbinds?: Array<Varbind>, options?: SimplePduOptions)
    {
        super(id, varbinds, options)
        this.type = PduType.GetBulkRequest;
    }

    static createFromBuffer (reader: Reader): GetBulkRequestPdu {
        const pdu = new GetBulkRequestPdu ();
        pdu.initializeFromBuffer (reader);
        return pdu;
    }
}

class GetNextRequestPdu
    extends SimplePdu
{
    constructor(id?: number, varbinds?: Array<Varbind>, options?: SimplePduOptions)
    {
        super(id, varbinds, options)
        this.type = PduType.GetNextRequest;
    }

    static createFromBuffer (reader: Reader): GetNextRequestPdu {
        const pdu = new GetNextRequestPdu ();
        pdu.initializeFromBuffer (reader);
        return pdu;
    }
}

class GetRequestPdu
    extends SimplePdu
{
    constructor (id?: number, varbinds?: Array<Varbind>, options?: SimplePduOptions)
    {
        super(id, varbinds, options)
	    this.type = PduType.GetRequest;
    }

    static createFromBuffer (reader: Reader): GetRequestPdu {
	    const pdu = new GetRequestPdu();
	    pdu.initializeFromBuffer (reader);
	    return pdu;
    }

    static createFromVariables (id: number, varbinds: Array<Varbind>, options?: SimplePduOptions): GetRequestPdu {
        const pdu = new GetRequestPdu();
        pdu.initializeFromVariables (id, varbinds, options);
        return pdu;
    }
};

class InformRequestPdu
    extends SimplePdu
{
    constructor (id?: number, varbinds?: Array<Varbind>, options?: SimplePduOptions)
    {
        super(id, varbinds, options)
	    this.type = PduType.InformRequest;
    }

    static createFromBuffer (reader: Reader): InformRequestPdu {
	    const pdu = new InformRequestPdu();
	    pdu.initializeFromBuffer (reader);
	    return pdu;
    }
};

class SetRequestPdu
    extends SimplePdu
{
    constructor (id?: number, varbinds?: Array<Varbind>, options?: SimplePduOptions)
    {
        super(id, varbinds, options)
	    this.type = PduType.SetRequest;
    }

    static createFromBuffer (reader: Reader): SetRequestPdu {
	    const pdu = new SetRequestPdu ();
	    pdu.initializeFromBuffer (reader);
	    return pdu;
    }
};

class TrapPdu
    extends SimplePdu
{
    protected enterprise: string;
    protected upTime: number;
    protected agentAddr: string;
    protected generic: number;
    protected specific: number;

    constructor (id?: number, varbinds?: Array<Varbind>, options?: SimplePduOptions)
    {
        super(id, varbinds, options)
        this.type = PduType.Trap;

        this.enterprise = "";
        this.upTime = 0;
        this.agentAddr = "";
        this.generic = 0;
        this.specific = 0;
    }

    override toBuffer (buffer: Writer): void {
        buffer.startSequence (this.type);

        buffer.writeOID (this.enterprise);
        buffer.writeBuffer (Buffer.from (this.agentAddr.split (".") as any),
                ObjectType.IpAddress);
        writeInt32 (buffer, ObjectType.Integer, this.generic);
        writeInt32 (buffer, ObjectType.Integer, this.specific);
        writeUint32 (buffer, ObjectType.TimeTicks,
                this.upTime || Math.floor (process.uptime () * 100));

        writeVarbinds (buffer, this.varbinds);

    	buffer.endSequence ();
    }

    static createFromBuffer (reader: Reader): TrapPdu {
        const pdu = new TrapPdu();
        reader.readSequence ();

        pdu.enterprise = reader.readOID ()!;
        pdu.agentAddr = readIpAddress (reader);
        pdu.generic = readInt32 (reader);
        pdu.specific = readInt32 (reader);
        pdu.upTime = readUint32 (reader);

        pdu.varbinds = [];
        readVarbinds (reader, pdu.varbinds);

    	return pdu;
    }

    static createFromVariables (typeOrOid: string | number, varbinds: Array<Varbind>, options: SimpleResponsePduOptions): TrapPdu {
	    const pdu = new TrapPdu ();
        pdu.agentAddr = options.agentAddr ?? "127.0.0.1";
        pdu.upTime = options.upTime!;

        if (typeof typeOrOid == "string") {
            pdu.generic = TrapType.EnterpriseSpecific;
            pdu.specific = parseInt (typeOrOid.match (/\.(\d+)$/)![1]!);
            pdu.enterprise = typeOrOid.replace (/\.(\d+)$/, "");
        } else {
            pdu.generic = typeOrOid;
            pdu.specific = 0;
            pdu.enterprise = "1.3.6.1.4.1";
        }

        pdu.varbinds = varbinds;

        return pdu;
    }
}

class TrapV2Pdu
    extends SimplePdu
{
    constructor (id?: number, varbinds?: Array<Varbind>, options?: SimplePduOptions)
    {
        super(id, varbinds, options)
        this.type = PduType.TrapV2;
    }

    static createFromBuffer (reader: Reader): TrapV2Pdu {
        const pdu = new TrapV2Pdu();
        pdu.initializeFromBuffer (reader);
        return pdu;
    }

    static createFromVariables (id: number, varbinds: Array<Varbind>, options?: SimplePduOptions): TrapV2Pdu {
        const pdu = new TrapV2Pdu();
        pdu.initializeFromVariables (id, varbinds, options);
        return pdu;
    }
};

type SimpleResponsePduOptions = {
    agentAddr?: string;
    upTime?: number;
}

class SimpleResponsePdu
{
    id: number
    type: number
    errorStatus: ErrorStatusKey;
    errorIndex: number;
    varbinds: Array<Varbind>;
    protected options: SimpleResponsePduOptions;

    contextEngineID: Buffer | undefined;
    contextName: string;
    scoped: boolean;

    constructor ()
    {
        this.id = 0;
        this.type = 0;
        this.errorStatus = ErrorStatus.NoError;
        this.errorIndex = 0;
        this.varbinds = [];
        this.options = {}

        this.contextEngineID = undefined;
        this.contextName = "";
        this.scoped = false;
    }

    toBuffer (writer: Writer) {
	    writer.startSequence (this.type);

        writeInt32 (writer, ObjectType.Integer, this.id);
        writeInt32 (writer, ObjectType.Integer, this.errorStatus || 0);
        writeInt32 (writer, ObjectType.Integer, this.errorIndex || 0);
        writeVarbinds (writer, this.varbinds);
        writer.endSequence ();
    }

    initializeFromBuffer (reader: Reader) {
	    reader.readSequence (this.type);

        this.id = readInt32 (reader);
        this.errorStatus = readInt32 (reader);
        this.errorIndex = readInt32 (reader);

        this.varbinds = [];
        readVarbinds (reader, this.varbinds);
    }

    initializeFromVariables (id: number, varbinds: Array<Varbind>, options?: SimpleResponsePduOptions) {
	    this.id = id;
	    this.varbinds = varbinds;
	    this.options = options || {};
    }
};

class GetResponsePdu
    extends SimpleResponsePdu
{
    constructor()
    {
        super()
        this.type = PduType.GetResponse;
    }

    static createFromBuffer (reader: Reader): GetResponsePdu {
        const pdu = new GetResponsePdu ();
        pdu.initializeFromBuffer (reader);
        return pdu;
    }

    static createFromVariables (id: number, varbinds: Array<Varbind>, options?: SimpleResponsePduOptions): GetResponsePdu {
        const pdu = new GetResponsePdu();
        pdu.initializeFromVariables (id, varbinds, options);
        return pdu;
    };
}

class ReportPdu
    extends SimpleResponsePdu
{
    constructor ()
    {
        super()
	    this.type = PduType.Report;
    }

    static createFromBuffer (reader: Reader): ReportPdu {
        const pdu = new ReportPdu ();
        pdu.initializeFromBuffer (reader);
        return pdu;
    }

    static createFromVariables (id: number, varbinds: Array<Varbind>, options?: SimpleResponsePduOptions): ReportPdu {
	    const pdu = new ReportPdu();
	    pdu.initializeFromVariables (id, varbinds, options);
	    return pdu;
    }
};

function readPdu (reader: Reader, scoped: boolean): SimplePdu | SimpleResponsePdu {
	let pdu: SimplePdu | SimpleResponsePdu | null = null;
	let contextEngineID: Buffer | undefined;
	let contextName: string | undefined;
	if ( scoped ) {
		reader = new ber.Reader (reader.readString (ber.Sequence | ber.Constructor, true) as Buffer);
		contextEngineID = reader.readString (ber.OctetString, true) as Buffer;
		contextName = reader.readString () as string;
	}
	const type = reader.peek ();

    switch (type)
    {
	    case PduType.GetResponse:
		    pdu = GetResponsePdu.createFromBuffer (reader);
	    case PduType.Report:
		    pdu = ReportPdu.createFromBuffer (reader);
	    case PduType.Trap:
		    pdu = TrapPdu.createFromBuffer (reader);
	    case PduType.TrapV2:
		    pdu = TrapV2Pdu.createFromBuffer (reader);
	    case PduType.InformRequest:
		    pdu = InformRequestPdu.createFromBuffer (reader);
	    case PduType.GetRequest:
		    pdu = GetRequestPdu.createFromBuffer (reader);
	    case PduType.SetRequest:
		    pdu = SetRequestPdu.createFromBuffer (reader);
	    case PduType.GetNextRequest:
		    pdu = GetNextRequestPdu.createFromBuffer (reader);
	    case PduType.GetBulkRequest:
		    pdu = GetBulkRequestPdu.createFromBuffer (reader);
	    default:
		    throw new ResponseInvalidError ("Unknown PDU type '" + type
				+ "' in response", ResponseInvalidCode.EUnknownPduType);
	}
	if ( scoped ) {
		pdu!.contextEngineID = contextEngineID!;
		pdu!.contextName = contextName!;
	}
	pdu!.scoped = scoped;
	return pdu!;
};

function createDiscoveryPdu (context: string): GetRequestPdu {
	return GetRequestPdu.createFromVariables(_generateId(), [], {context: context});
};

type AuthenticationAlgorithmsKeys = keyof typeof Authentication.algorithms

export class Authentication
{
    static readonly HMAC_BUFFER_SIZE = 1024*1024
    static readonly algorithms = {
        [AuthProtocols.md5]: {
            KEY_LENGTH: 16,
            AUTHENTICATION_CODE_LENGTH: 12,
            CRYPTO_ALGORITHM: 'md5'
        },
        [AuthProtocols.sha]: {
            KEY_LENGTH: 20,
            AUTHENTICATION_CODE_LENGTH: 12,
            CRYPTO_ALGORITHM: 'sha1'
        },
        [AuthProtocols.sha224]: {
            KEY_LENGTH: 28,
            AUTHENTICATION_CODE_LENGTH: 16,
            CRYPTO_ALGORITHM: 'sha224'
        },
        [AuthProtocols.sha256]: {
            KEY_LENGTH: 32,
            AUTHENTICATION_CODE_LENGTH: 24,
            CRYPTO_ALGORITHM: 'sha256'
        },
        [AuthProtocols.sha384]: {
            KEY_LENGTH: 48,
            AUTHENTICATION_CODE_LENGTH: 32,
            CRYPTO_ALGORITHM: 'sha384'
        },
        [AuthProtocols.sha512]: {
            KEY_LENGTH: 64,
            AUTHENTICATION_CODE_LENGTH: 48,
            CRYPTO_ALGORITHM: 'sha512'
        }
    };

    static authToKeyCache: {[name: string]: Buffer} = {}

    static computeCacheKey (authProtocol: AuthenticationAlgorithmsKeys, authPasswordString: string, engineID: Buffer): string {
	    const engineIDString = engineID.toString('base64');
	    return authProtocol + authPasswordString + engineIDString;
    }

    // Adapted from RFC3414 Appendix A.2.1. Password to Key Sample Code for MD5
    static passwordToKey (authProtocol: AuthenticationAlgorithmsKeys, authPasswordString: string, engineID: Buffer): Buffer {
        const cryptoAlgorithm = Authentication.algorithms[authProtocol].CRYPTO_ALGORITHM;

        const cacheKey = Authentication.computeCacheKey(authProtocol, authPasswordString, engineID);
        if (Authentication.authToKeyCache[cacheKey] !== undefined) {
            return Authentication.authToKeyCache[cacheKey]!;
        }

        const buf = Buffer.alloc (Authentication.HMAC_BUFFER_SIZE, authPasswordString);

        let hashAlgorithm = createHash(cryptoAlgorithm);
        hashAlgorithm.update(buf);
        const firstDigest = hashAlgorithm.digest();
        // debug ("First digest:  " + firstDigest.toString('hex'));

        hashAlgorithm = createHash(cryptoAlgorithm);
        hashAlgorithm.update(firstDigest);
        hashAlgorithm.update(engineID);
        hashAlgorithm.update(firstDigest);
        const finalDigest = hashAlgorithm.digest();
        // debug ("Localized key: " + finalDigest.toString('hex'));

        Authentication.authToKeyCache[cacheKey] = finalDigest;
        return finalDigest;
    }

    static getParametersLength (authProtocol: AuthenticationAlgorithmsKeys): number {
	    return Authentication.algorithms[authProtocol].AUTHENTICATION_CODE_LENGTH;
    }

    static writeParameters (messageBuffer: Buffer, authProtocol: AuthenticationAlgorithmsKeys, authPassword: string, engineID: Buffer, digestInMessage: Buffer): void {
	    let digestToAdd = Authentication.calculateDigest (messageBuffer, authProtocol, authPassword, engineID);
	    digestToAdd.copy (digestInMessage);
	    // debug ("Added Auth Parameters: " + digestToAdd.toString('hex'));
    }

    static isAuthentic (messageBuffer: Buffer, authProtocol: AuthenticationAlgorithmsKeys, authPassword: string, engineID: Buffer, digestInMessage: Buffer): boolean {
        if (digestInMessage.length !== Authentication.algorithms[authProtocol].AUTHENTICATION_CODE_LENGTH)
            return false;

        // save original authenticationParameters field in message
        const savedDigest = Buffer.from (digestInMessage);

        // clear the authenticationParameters field in message
        digestInMessage.fill (0);

        const calculatedDigest = Authentication.calculateDigest (messageBuffer, authProtocol, authPassword, engineID);

        // replace previously cleared authenticationParameters field in message
        savedDigest.copy (digestInMessage);

        // debug ("Digest in message: " + digestInMessage.toString('hex'));
        // debug ("Calculated digest: " + calculatedDigest.toString('hex'));
        return calculatedDigest.equals (digestInMessage);
    }

    static calculateDigest (messageBuffer: Buffer, authProtocol: AuthenticationAlgorithmsKeys, authPassword: string, engineID: Buffer): Buffer {
	    const authKey = Authentication.passwordToKey (authProtocol, authPassword, engineID);

	    const cryptoAlgorithm = Authentication.algorithms[authProtocol].CRYPTO_ALGORITHM;
	    const hmacAlgorithm = createHmac (cryptoAlgorithm, authKey);
	    hmacAlgorithm.update (messageBuffer);
	    const digest = hmacAlgorithm.digest ();
	    return digest.subarray (0, Authentication.algorithms[authProtocol].AUTHENTICATION_CODE_LENGTH);
    }
}

type EncryptionAlgorithmsKeys = keyof typeof Encryption.algorithms;
type EncryptionAlgorithm = Values<typeof Encryption.algorithms>
type PrivacyParameters = Buffer | string;

export class Encryption
{
    static encryptPdu (privProtocol: EncryptionAlgorithmsKeys, scopedPdu: Buffer, privPassword: Buffer, authProtocol: AuthenticationAlgorithmsKeys, engine: Engine) {
	    const encryptFunction = Encryption.algorithms[privProtocol].encryptPdu;
	    return encryptFunction (scopedPdu, privProtocol, privPassword, authProtocol, engine);
    }

    static decryptPdu (privProtocol: EncryptionAlgorithmsKeys, encryptedPdu: Buffer, privParameters: PrivacyParameters, privPassword: Buffer, authProtocol: AuthenticationAlgorithmsKeys, engine: Engine) {
	    const decryptFunction = Encryption.algorithms[privProtocol].decryptPdu;
	    return decryptFunction (encryptedPdu, privProtocol, privParameters, privPassword, authProtocol, engine);
    }

    static debugEncrypt (encryptionKey: Buffer, iv: Buffer, plainPdu: Buffer, encryptedPdu: Buffer): void {
        debug ("Key: " + encryptionKey.toString ('hex'));
        debug ("IV:  " + iv.toString ('hex'));
        debug ("Plain:     " + plainPdu.toString ('hex'));
        debug ("Encrypted: " + encryptedPdu.toString ('hex'));
    }

    static debugDecrypt (decryptionKey: Buffer, iv: Buffer, encryptedPdu: Buffer, plainPdu: Buffer): void {
        debug ("Key: " + decryptionKey.toString ('hex'));
        debug ("IV:  " + iv.toString ('hex'));
        debug ("Encrypted: " + encryptedPdu.toString ('hex'));
        debug ("Plain:     " + plainPdu.toString ('hex'));
    }

    static generateLocalizedKey (algorithm: EncryptionAlgorithm, authProtocol: AuthenticationAlgorithmsKeys, privPassword: Buffer, engineID: Buffer): Buffer {
        const privLocalizedKey = Authentication.passwordToKey (authProtocol, privPassword, engineID);
        const encryptionKey = Buffer.alloc (algorithm.KEY_LENGTH);
        privLocalizedKey.copy (encryptionKey, 0, 0, algorithm.KEY_LENGTH);

        return encryptionKey;
    }

    static generateLocalizedKeyBlumenthal (algorithm: EncryptionAlgorithm, authProtocol: AuthenticationAlgorithmsKeys, privPassword: string, engineID: Buffer): Buffer {
        const authKeyLength = Authentication.algorithms[authProtocol].KEY_LENGTH;
        const rounds = Math.ceil (algorithm.KEY_LENGTH / authKeyLength );
        const encryptionKey = Buffer.alloc (algorithm.KEY_LENGTH);
        const privLocalizedKey = Authentication.passwordToKey (authProtocol, privPassword, engineID);
        let nextHash = privLocalizedKey;

        for ( let round = 0 ; round < rounds ; round++ ) {
            nextHash.copy (encryptionKey, round * authKeyLength, 0, authKeyLength);
            if ( round < rounds - 1 ) {
                const hashAlgorithm = createHash (Authentication.algorithms[authProtocol].CRYPTO_ALGORITHM);
                const hashInput = Buffer.alloc ( (round + 1) * authKeyLength);
                encryptionKey.copy (hashInput, round * authKeyLength, 0, (round + 1) * authKeyLength);
                hashAlgorithm.update (hashInput);
                nextHash = hashAlgorithm.digest ();
            }
        }

        return encryptionKey;
    }

    static generateLocalizedKeyReeder (algorithm: EncryptionAlgorithm, authProtocol: AuthenticationAlgorithmsKeys, privPassword: Buffer, engineID: Buffer): Buffer {
        const authKeyLength = Authentication.algorithms[authProtocol].KEY_LENGTH;
        const rounds = Math.ceil (algorithm.KEY_LENGTH / authKeyLength );
        const encryptionKey = Buffer.alloc (algorithm.KEY_LENGTH);
        let nextPasswordInput = privPassword;

        for ( let round = 0 ; round < rounds ; round++ ) {
            const privLocalizedKey = Authentication.passwordToKey (authProtocol, nextPasswordInput, engineID);
            privLocalizedKey.copy (encryptionKey, round * authKeyLength, 0, authKeyLength);
            nextPasswordInput = privLocalizedKey;
        }

        return encryptionKey;
    }

    static encryptPduDes (scopedPdu: Buffer, privProtocol: EncryptionAlgorithmsKeys, privPassword: Buffer, authProtocol: AuthenticationAlgorithmsKeys, engine: Engine) {
        const des = Encryption.algorithms[PrivProtocols.des];

        // @bug: maybe bug, since this var is unused
        const encryptionKeyLocal = Encryption.generateLocalizedKey (des, authProtocol, privPassword, engine.engineID);
        const privLocalizedKey = Authentication.passwordToKey (authProtocol, privPassword, engine.engineID);
        const encryptionKey = Buffer.alloc (des.KEY_LENGTH);
        privLocalizedKey.copy (encryptionKey, 0, 0, des.KEY_LENGTH);
        const preIv = Buffer.alloc (des.BLOCK_LENGTH);
        privLocalizedKey.copy (preIv, 0, des.KEY_LENGTH, des.KEY_LENGTH + des.BLOCK_LENGTH);

        const salt = Buffer.alloc (des.BLOCK_LENGTH);
        // set local SNMP engine boots part of salt to 1, as we have no persistent engine state
        salt.fill ('00000001', 0, 4, 'hex');
        // set local integer part of salt to random
        salt.fill (randomBytes (4), 4, 8);
        const iv = Buffer.alloc (des.BLOCK_LENGTH);
        for (let i = 0; i < iv.length; i++) {
            iv[i] = (preIv[i] ?? 0) ^ (salt[i] ?? 0);
        }

        let paddedScopedPdu;
        if (scopedPdu.length % des.BLOCK_LENGTH == 0) {
            paddedScopedPdu = scopedPdu;
        } else {
            const paddedScopedPduLength = des.BLOCK_LENGTH * (Math.floor (scopedPdu.length / des.BLOCK_LENGTH) + 1);
            paddedScopedPdu = Buffer.alloc (paddedScopedPduLength);
            scopedPdu.copy (paddedScopedPdu, 0, 0, scopedPdu.length);
        }
        const cipher = createCipheriv (des.CRYPTO_ALGORITHM, encryptionKey, iv);
        let encryptedPdu = cipher.update (paddedScopedPdu);
        encryptedPdu = Buffer.concat ([encryptedPdu, cipher.final()]);
        // Encryption.debugEncrypt (encryptionKey, iv, paddedScopedPdu, encryptedPdu);

        return {
            encryptedPdu: encryptedPdu,
            msgPrivacyParameters: salt
        };
    }

    static decryptPduDes (encryptedPdu: Buffer, privProtocol: EncryptionAlgorithmsKeys, privParameters: PrivacyParameters, privPassword: string, authProtocol: AuthenticationAlgorithmsKeys, engine: Engine): Buffer {
        const des = Encryption.algorithms[PrivProtocols.des];

        const privLocalizedKey = Authentication.passwordToKey (authProtocol, privPassword, engine.engineID);
        const decryptionKey = Buffer.alloc (des.KEY_LENGTH);
        privLocalizedKey.copy (decryptionKey, 0, 0, des.KEY_LENGTH);
        const preIv = Buffer.alloc (des.BLOCK_LENGTH);
        privLocalizedKey.copy (preIv, 0, des.KEY_LENGTH, des.KEY_LENGTH + des.BLOCK_LENGTH);

        const salt = privParameters;
        const iv = Buffer.alloc (des.BLOCK_LENGTH);
        for (let i = 0; i < iv.length; i++) {
            iv[i] = (preIv[i] ?? 0) ^ (salt[i] ?? 0);
        }

        const decipher = createDecipheriv (des.CRYPTO_ALGORITHM, decryptionKey, iv);
        decipher.setAutoPadding(false);
        let decryptedPdu = decipher.update (encryptedPdu);
        decryptedPdu = Buffer.concat ([decryptedPdu, decipher.final()]);
        // Encryption.debugDecrypt (decryptionKey, iv, encryptedPdu, decryptedPdu);

        return decryptedPdu;
    }

    static generateIvAes (aes: EncryptionAlgorithm, engineBoots: number, engineTime: number, salt: Buffer) {
        // iv = engineBoots(4) | engineTime(4) | salt(8)
        const iv = Buffer.alloc (aes.BLOCK_LENGTH);
        const engineBootsBuffer = Buffer.alloc (4);
        engineBootsBuffer.writeUInt32BE (engineBoots);
        const engineTimeBuffer = Buffer.alloc (4);
        engineTimeBuffer.writeUInt32BE (engineTime);
        engineBootsBuffer.copy (iv, 0, 0, 4);
        engineTimeBuffer.copy (iv, 4, 0, 4);
        salt.copy (iv, 8, 0, 8);

        return iv;
    }

    static encryptPduAes (scopedPdu: Buffer, privProtocol: EncryptionAlgorithmsKeys, privPassword: Buffer, authProtocol: AuthenticationAlgorithmsKeys, engine: Engine) {
        const  aes = Encryption.algorithms[privProtocol];
        const localizationAlgorithm = aes.localizationAlgorithm;

        const encryptionKey = localizationAlgorithm (aes, authProtocol, privPassword, engine.engineID);
        const salt = Buffer.alloc (8).fill (randomBytes (8), 0, 8);
        const iv = Encryption.generateIvAes (aes, engine.engineBoots, engine.engineTime, salt);
        const cipher = createCipheriv (aes.CRYPTO_ALGORITHM, encryptionKey, iv);
        let encryptedPdu = cipher.update (scopedPdu);
        encryptedPdu = Buffer.concat ([encryptedPdu, cipher.final()]);
        // Encryption.debugEncrypt (encryptionKey, iv, scopedPdu, encryptedPdu);

        return {
            encryptedPdu: encryptedPdu,
            msgPrivacyParameters: salt
        };
    }

    static decryptPduAes (encryptedPdu: Buffer, privProtocol: EncryptionAlgorithmsKeys, privParameters: PrivacyParameters, privPassword: Buffer, authProtocol: AuthenticationAlgorithmsKeys, engine: Engine) {
        const aes = Encryption.algorithms[privProtocol];
        const localizationAlgorithm = aes.localizationAlgorithm;

        const decryptionKey = localizationAlgorithm (aes, authProtocol, privPassword, engine.engineID);
        const iv = Encryption.generateIvAes (aes, engine.engineBoots, engine.engineTime, privParameters);
        const decipher = createDecipheriv (aes.CRYPTO_ALGORITHM, decryptionKey, iv);
        let decryptedPdu = decipher.update (encryptedPdu);
        decryptedPdu = Buffer.concat ([decryptedPdu, decipher.final()]);
        // Encryption.debugDecrypt (decryptionKey, iv, encryptedPdu, decryptedPdu);

        return decryptedPdu;
    }

    static readonly algorithms = {
        [PrivProtocols.des]: {
            CRYPTO_ALGORITHM: 'des-cbc',
            KEY_LENGTH: 8,
            BLOCK_LENGTH: 8,
            encryptPdu: Encryption.encryptPduDes,
            decryptPdu: Encryption.decryptPduDes,
            localizationAlgorithm: Encryption.generateLocalizedKey
        },
        [PrivProtocols.aes]: {
            CRYPTO_ALGORITHM: 'aes-128-cfb',
            KEY_LENGTH: 16,
            BLOCK_LENGTH: 16,
            encryptPdu: Encryption.encryptPduAes,
            decryptPdu: Encryption.decryptPduAes,
            localizationAlgorithm: Encryption.generateLocalizedKey
        },
        [PrivProtocols.aes256b]: {
            CRYPTO_ALGORITHM: 'aes-256-cfb',
            KEY_LENGTH: 32,
            BLOCK_LENGTH: 16,
            encryptPdu: Encryption.encryptPduAes,
            decryptPdu: Encryption.decryptPduAes,
            localizationAlgorithm: Encryption.generateLocalizedKeyBlumenthal
        },
        [PrivProtocols.aes256r]: {
            CRYPTO_ALGORITHM: 'aes-256-cfb',
            KEY_LENGTH: 32,
            BLOCK_LENGTH: 16,
            encryptPdu: Encryption.encryptPduAes,
            decryptPdu: Encryption.decryptPduAes,
            localizationAlgorithm: Encryption.generateLocalizedKeyReeder
        }
    };
}

/*****************************************************************************
 ** Message class definition
 **/


type InputMsgSecurityParameters = {
    msgAuthoritativeEngineID?: Buffer;
    msgAuthoritativeEngineBoots?: number;
    msgAuthoritativeEngineTime?: number;
}

type MsgSecurityParameters = {
    msgAuthoritativeEngineID: Buffer;
    msgAuthoritativeEngineBoots: number;
    msgAuthoritativeEngineTime: number;
    msgUserName: string;
    msgPrivacyParameters: PrivacyParameters;
    msgAuthenticationParameters: Buffer | string;
}

type MsgGlobalData = {
    msgID: number;
    msgMaxSize: number;
    msgFlags?: number;
    msgSecurityModel: number;
}

class Message
{
    version: SecurityModel;
    msgGlobalData: MsgGlobalData | undefined;
    pdu: SimplePdu | SimpleResponsePdu | null;
    buffer: Buffer;
    community: string;
    user: ;
    msgSecurityParameters: MsgSecurityParameters;
    encryptedPdu: Buffer;
    disableAuthentication: boolean;

    constructor () {
        this.version = Version3;
        this.msgGlobalData = undefined;
        this.pdu = null;
        this.buffer = Buffer.alloc(0);
        this.community = "";
        this.user = ;
        this.msgSecurityParameters = {
            msgAuthoritativeEngineID: Buffer.alloc(0),
            msgAuthoritativeEngineBoots: 0,
            msgAuthoritativeEngineTime: 0,
            msgUserName: "",
            msgPrivacyParameters: "",
            msgAuthenticationParameters: ""
        };
        this.encryptedPdu = Buffer.alloc(0);
        this.disableAuthentication = false;
    }

    getReqId (): number {
	    return this.version == Version3 ? this.msgGlobalData!.msgID : this.pdu!.id;
    }

    toBuffer (): Buffer {
        if ( this.version == Version3 ) {
            return this.toBufferV3();
        } else {
            return this.toBufferCommunity();
        }
    }

    toBufferCommunity (): Buffer {
        if (this.buffer)
            return this.buffer;

        const writer = new ber.Writer ();

        writer.startSequence ();

        writeInt32 (writer, ObjectType.Integer, this.version);
        writer.writeString (this.community);

        this.pdu!.toBuffer (writer);

        writer.endSequence ();

        this.buffer = writer.buffer;

        return this.buffer;
    }

    toBufferV3 (): Buffer {
        let encryptionResult;

        if (this.buffer)
            return this.buffer;

        // ScopedPDU
        const scopedPduWriter = new ber.Writer ();
        scopedPduWriter.startSequence ();
        const contextEngineID = this.pdu!.contextEngineID ? this.pdu!.contextEngineID : this.msgSecurityParameters.msgAuthoritativeEngineID;
        if ( contextEngineID.length == 0 ) {
            scopedPduWriter.writeString ("");
        } else {
            scopedPduWriter.writeBuffer (contextEngineID, ber.OctetString);
        }
        scopedPduWriter.writeString (this.pdu!.contextName);
        this.pdu!.toBuffer (scopedPduWriter);
        scopedPduWriter.endSequence ();

        if ( this.hasPrivacy() ) {
            const authoritativeEngine = new Engine(
                this.msgSecurityParameters.msgAuthoritativeEngineID,
                this.msgSecurityParameters.msgAuthoritativeEngineBoots,
                this.msgSecurityParameters.msgAuthoritativeEngineTime,
            );
            encryptionResult = Encryption.encryptPdu (this.user.privProtocol, scopedPduWriter.buffer,
                    this.user.privKey, this.user.authProtocol, authoritativeEngine);
        }

        const writer = new ber.Writer ();

        writer.startSequence ();

        writeInt32 (writer, ObjectType.Integer, this.version);

        // HeaderData
        writer.startSequence ();
        writeInt32 (writer, ObjectType.Integer, this.msgGlobalData!.msgID);
        writeInt32 (writer, ObjectType.Integer, this.msgGlobalData!.msgMaxSize);
        writer.writeByte (ber.OctetString);
        writer.writeByte (1);
        writer.writeByte (this.msgGlobalData!.msgFlags!);
        writeInt32 (writer, ObjectType.Integer, this.msgGlobalData!.msgSecurityModel);
        writer.endSequence ();

        // msgSecurityParameters
        writer.startSequence (ber.OctetString);
        writer.startSequence ();
        //writer.writeString (this.msgSecurityParameters.msgAuthoritativeEngineID);
        // writing a zero-length buffer fails - should fix asn1-ber for this condition
        if ( this.msgSecurityParameters.msgAuthoritativeEngineID.length == 0 ) {
            writer.writeString ("");
        } else {
            writer.writeBuffer (this.msgSecurityParameters.msgAuthoritativeEngineID, ber.OctetString);
        }
        writeInt32 (writer, ObjectType.Integer, this.msgSecurityParameters.msgAuthoritativeEngineBoots);
        writeInt32 (writer, ObjectType.Integer, this.msgSecurityParameters.msgAuthoritativeEngineTime);
        writer.writeString (this.msgSecurityParameters.msgUserName);

        let msgAuthenticationParameters: Buffer | string = '';
        if ( this.hasAuthentication() ) {
            var authParametersLength = Authentication.getParametersLength (this.user.authProtocol);
            msgAuthenticationParameters = Buffer.alloc (authParametersLength);
            writer.writeBuffer (msgAuthenticationParameters, ber.OctetString);
        } else {
            writer.writeString ("");
        }
        var msgAuthenticationParametersOffset = writer._offset - msgAuthenticationParameters.length;

        if ( this.hasPrivacy() ) {
            writer.writeBuffer (encryptionResult!.msgPrivacyParameters, ber.OctetString);
        } else {
            writer.writeString ("");
        }
        msgAuthenticationParametersOffset -= writer._offset;
        writer.endSequence ();
        writer.endSequence ();
        msgAuthenticationParametersOffset += writer._offset;

        if ( this.hasPrivacy() ) {
            writer.writeBuffer (encryptionResult!.encryptedPdu, ber.OctetString);
        } else {
            writer.writeBuffer (scopedPduWriter.buffer);
        }

        msgAuthenticationParametersOffset -= writer._offset;
        writer.endSequence ();
        msgAuthenticationParametersOffset += writer._offset;

        this.buffer = writer.buffer;

        if ( this.hasAuthentication() ) {
            msgAuthenticationParameters = this.buffer.subarray (msgAuthenticationParametersOffset,
                msgAuthenticationParametersOffset + msgAuthenticationParameters.length);
            Authentication.writeParameters (this.buffer, this.user.authProtocol, this.user.authKey,
                this.msgSecurityParameters.msgAuthoritativeEngineID, msgAuthenticationParameters);
        }

        return this.buffer;
    };

    processIncomingSecurity (user, responseCb: (error: Error) => void): boolean {
        if ( this.hasPrivacy() ) {
            if ( ! this.decryptPdu(user, responseCb) ) {
                return false;
            }
        }

        if ( this.hasAuthentication() && ! this.isAuthenticationDisabled() ) {
            return this.checkAuthentication(user, responseCb);
        } else {
            return true;
        }
    }

    decryptPdu (user, responseCb: (error: Error) => void): boolean {
        var decryptedPdu;
        var decryptedPduReader;
        try {
            var authoratitiveEngine = new Engine(
                this.msgSecurityParameters.msgAuthoritativeEngineID,
                this.msgSecurityParameters.msgAuthoritativeEngineBoots,
                this.msgSecurityParameters.msgAuthoritativeEngineTime
            );
            decryptedPdu = Encryption.decryptPdu(user.privProtocol, this.encryptedPdu,
                    this.msgSecurityParameters.msgPrivacyParameters, user.privKey, user.authProtocol,
                    authoratitiveEngine);
            decryptedPduReader = new ber.Reader (decryptedPdu);
            this.pdu = readPdu(decryptedPduReader, true);
            return true;
        } catch (error) {
            responseCb (new ResponseInvalidError ("Failed to decrypt PDU: " + error,
                    ResponseInvalidCode.ECouldNotDecrypt));
            return false;
        }

    }

    checkAuthentication (user, responseCb: (error: Error) => void): boolean {
        if ( Authentication.isAuthentic(this.buffer, user.authProtocol, user.authKey,
                this.msgSecurityParameters.msgAuthoritativeEngineID, this.msgSecurityParameters.msgAuthenticationParameters as Buffer) ) {
            return true;
        } else {
            responseCb (new ResponseInvalidError ("Authentication digest "
                    + this.msgSecurityParameters.msgAuthenticationParameters.toString ('hex')
                    + " received in message does not match digest "
                    + Authentication.calculateDigest (this.buffer, user.authProtocol, user.authKey,
                        this.msgSecurityParameters.msgAuthoritativeEngineID).toString ('hex')
                    + " calculated for message", ResponseInvalidCode.EAuthFailure, { user }));
            return false;
        }
    }

    setMsgFlags (bitPosition: number, flag: boolean): void {
        if ( this.msgGlobalData && this.msgGlobalData !== undefined && this.msgGlobalData !== null ) {
            if ( flag ) {
                this.msgGlobalData.msgFlags = this.msgGlobalData!.msgFlags! | ( 2 ** bitPosition );
            } else {
                this.msgGlobalData.msgFlags = this.msgGlobalData!.msgFlags! & ( 255 - 2 ** bitPosition );
            }
        }
    }

    hasAuthentication (): boolean {
	    return Boolean(this.msgGlobalData && this.msgGlobalData.msgFlags && this.msgGlobalData.msgFlags & 1);
    };

    setAuthentication (flag: boolean): void {
	    this.setMsgFlags (0, flag);
    };

    hasPrivacy (): boolean {
	    return Boolean(this.msgGlobalData && this.msgGlobalData.msgFlags && this.msgGlobalData.msgFlags & 2);
    }

    setPrivacy (flag: boolean): void {
        this.setMsgFlags (1, flag);
    }

    isReportable (): boolean {
        return Boolean(this.msgGlobalData && this.msgGlobalData.msgFlags && this.msgGlobalData.msgFlags & 4);
    }

    setReportable (flag: boolean): void {
        this.setMsgFlags (2, flag);
    }

    isAuthenticationDisabled (): boolean {
        return this.disableAuthentication;
    }

    hasAuthoritativeEngineID (): boolean {
        return Boolean(this.msgSecurityParameters && this.msgSecurityParameters.msgAuthoritativeEngineID &&
            this.msgSecurityParameters.msgAuthoritativeEngineID.length !== 0);
    }

    createReportResponseMessage (engine: Engine, context: string): Message {
        const user = {
            name: "",
            level: SecurityLevel.noAuthNoPriv
        };
        const responseSecurityParameters = {
            msgAuthoritativeEngineID: engine.engineID,
            msgAuthoritativeEngineBoots: engine.engineBoots,
            msgAuthoritativeEngineTime: engine.engineTime,
            msgUserName: user.name,
            msgAuthenticationParameters: "",
            msgPrivacyParameters: ""
        };
        const reportPdu = ReportPdu.createFromVariables (this.pdu!.id, [], {});
        reportPdu.contextName = context;
        const responseMessage = Message.createRequestV3 (user, responseSecurityParameters, reportPdu);
        responseMessage.msgGlobalData!.msgID = this.msgGlobalData!.msgID;
        return responseMessage;
    }

    createResponseForRequest (responsePdu: SimpleResponsePdu): Message {
        if ( this.version == Version3 ) {
            return this.createV3ResponseFromRequest(responsePdu);
        } else {
            return this.createCommunityResponseFromRequest(responsePdu);
        }
    }

    createCommunityResponseFromRequest (responsePdu: SimpleResponsePdu) {
        return Message.createCommunity(this.version, this.community, responsePdu);
    }

    createV3ResponseFromRequest (responsePdu: SimpleResponsePdu) {
        const responseUser = {
            name: this.user.name,
            level: this.user.level,
            authProtocol: this.user.authProtocol,
            authKey: this.user.authKey,
            privProtocol: this.user.privProtocol,
            privKey: this.user.privKey
        };
        const responseSecurityParameters = {
            msgAuthoritativeEngineID: this.msgSecurityParameters.msgAuthoritativeEngineID,
            msgAuthoritativeEngineBoots: this.msgSecurityParameters.msgAuthoritativeEngineBoots,
            msgAuthoritativeEngineTime: this.msgSecurityParameters.msgAuthoritativeEngineTime,
            msgUserName: this.msgSecurityParameters.msgUserName,
            msgAuthenticationParameters: "",
            msgPrivacyParameters: ""
        };
        const responseGlobalData = {
            msgID: this.msgGlobalData!.msgID,
            msgMaxSize: 65507,
            msgFlags: this.msgGlobalData!.msgFlags! & (255 - 4),
            msgSecurityModel: 3
        };
        return Message.createV3 (responseUser, responseGlobalData, responseSecurityParameters, responsePdu);
    }

    static createCommunity (version: SecurityModel, community: string, pdu: SimpleResponsePdu | SimplePdu) {
        const message = new Message ();

        message.version = version;
        message.community = community;
        message.pdu = pdu;

        return message;
    }

    static createRequestV3 (user, msgSecurityParameters: InputMsgSecurityParameters, pdu: SimplePdu | SimpleResponsePdu): Message {
        const authFlag = user.level == SecurityLevel.authNoPriv || user.level == SecurityLevel.authPriv ? 1 : 0;
        const privFlag = user.level == SecurityLevel.authPriv ? 1 : 0;
        const reportableFlag = ( pdu.type == PduType.GetResponse || pdu.type == PduType.TrapV2 ) ? 0 : 1;
        const msgGlobalData = {
            msgID: _generateId(), // random ID
            msgMaxSize: 65507,
            msgFlags: reportableFlag * 4 | privFlag * 2 | authFlag * 1,
            msgSecurityModel: 3
        };
        return Message.createV3 (user, msgGlobalData, msgSecurityParameters, pdu);
    }

    static createV3 (user, msgGlobalData: MsgGlobalData, msgSecurityParameters: InputMsgSecurityParameters, pdu: SimplePdu | SimpleResponsePdu): Message {
        const message = new Message ();

        message.version = 3;
        message.user = user;
        message.msgGlobalData = msgGlobalData;
        message.msgSecurityParameters = {
            msgAuthoritativeEngineID: msgSecurityParameters.msgAuthoritativeEngineID || Buffer.from(""),
            msgAuthoritativeEngineBoots: msgSecurityParameters.msgAuthoritativeEngineBoots || 0,
            msgAuthoritativeEngineTime: msgSecurityParameters.msgAuthoritativeEngineTime || 0,
            msgUserName: user.name || "",
            msgAuthenticationParameters: "",
            msgPrivacyParameters: ""
        };
        message.pdu = pdu;

        return message;
    }

    static createDiscoveryV3 (pdu: SimpleResponsePdu | SimplePdu): Message {
        const msgSecurityParameters = {
            msgAuthoritativeEngineID: Buffer.from(""),
            msgAuthoritativeEngineBoots: 0,
            msgAuthoritativeEngineTime: 0
        };
        const emptyUser = {
            name: "",
            level: SecurityLevel.noAuthNoPriv
        };
        return Message.createRequestV3 (emptyUser, msgSecurityParameters, pdu);
    }

    static createFromBuffer (buffer: Buffer, user?: string): Message {
        const reader = new ber.Reader (buffer);
        const message = new Message();

        reader.readSequence ();

        message.version = readInt32 (reader) as SecurityModel;

        if (message.version != 3) {
            message.community = reader.readString () as string;
            message.pdu = readPdu(reader, false);
        } else {
            // HeaderData
            message.msgGlobalData = {} as MsgGlobalData;
            reader.readSequence ();
            message.msgGlobalData.msgID = readInt32 (reader);
            message.msgGlobalData.msgMaxSize = readInt32 (reader);
            message.msgGlobalData.msgFlags = reader.readString (ber.OctetString, true)![0] as number;
            message.msgGlobalData.msgSecurityModel = readInt32 (reader);

            // msgSecurityParameters
            message.msgSecurityParameters = {} as MsgSecurityParameters;
            var msgSecurityParametersReader = new ber.Reader (reader.readString (ber.OctetString, true) as Buffer);
            msgSecurityParametersReader.readSequence ();
            message.msgSecurityParameters.msgAuthoritativeEngineID = msgSecurityParametersReader.readString (ber.OctetString, true) as Buffer;
            message.msgSecurityParameters.msgAuthoritativeEngineBoots = readInt32 (msgSecurityParametersReader);
            message.msgSecurityParameters.msgAuthoritativeEngineTime = readInt32 (msgSecurityParametersReader);
            message.msgSecurityParameters.msgUserName = msgSecurityParametersReader.readString () as string;
            message.msgSecurityParameters.msgAuthenticationParameters = msgSecurityParametersReader.readString (ber.OctetString, true)!;
            message.msgSecurityParameters.msgPrivacyParameters = Buffer.from(msgSecurityParametersReader.readString (ber.OctetString, true) as Buffer);

            if ( message.hasPrivacy() ) {
                message.encryptedPdu = reader.readString (ber.OctetString, true) as Buffer;
                message.pdu = null;
            } else {
                message.pdu = readPdu(reader, true);
            }
        }

        message.buffer = buffer;

        return message;
    }
}

type ReqOptions = {
    port?: number
}

class Req
{
    message: Message;
    responseCb: (error: Error | null, varbinds?: Array<Varbind | Array<Varbind>>) => void;
    feedCb: (req: Req, msg: Message) => void;
    retries: number;
    timeout: number;
    backoff: number | undefined;
    onResponse: (req: Req, msg: Message) => void;
    timer: NodeJS.Timeout | null
    port: number;
    context: string;

    constructor (session: Session, message: Message, feedCb: (req: Req, msg: Message) => void, responseCb: (error: Error | null, varbinds?: Array<Varbind | Array<Varbind>>) => void, options?: ReqOptions) {
        this.message = message;
        this.responseCb = responseCb;
        this.retries = session.retries;
        this.timeout = session.timeout;
        // Add timeout backoff
        this.backoff = session.backoff;
        this.onResponse = session.onSimpleGetResponse;
        this.feedCb = feedCb;
        this.port = (options && options.port) ? options.port : session.port;
        this.context = session.context;
        this.timer = null;
    }

    getId () {
	    return this.message.getReqId ();
    }
}


/*****************************************************************************
 ** Session class definition
 **/

function  _generateId (bitSize?: number): number {
    if (bitSize === 16) {
        return Math.floor(Math.random() * 10000) % 65535;
    }
    return Math.floor(Math.random() * 100000000) % 4294967295;
}

type SessionOptions = {
    version?: SecurityModel;
    transport?: SocketType;
    port?: number;
    trapPort?: number;
    retries?: number;
    timeout?: number;
    sourceAddress?: string;
    sourcePort?: string;
    backoff?: number;
    idBitsSize?: string;
    context?: string;
    backwardsGetNexts?: boolean;
    reportOidMismatchErrors?: boolean;
    debug?: boolean;
    engineID?: string | Buffer;
}

export class Session
    extends EventEmitter
{
    target: string;
    version: SecurityModel;
    community?: string;
    user: ;
    transport: SocketType;
    port: number;
    trapPort: number;
    retries: number;
    timeout: number;
    sourceAddress: string | undefined;
    sourcePort: number | undefined;
    backoff: number | undefined;
    idBitsSize: number;
    context: string;
    backwardsGetNexts: boolean;
    reportOidMismatchErrors: boolean;
    engine: Engine;
    reqs: {[id: number]: Req};
    reqCount: number;
    dgram: DgramSocket;
    msgSecurityParameters?: MsgSecurityParameters;

    constructor (target?: string, authenticator?: string, options?: SessionOptions) {
        super()

        this.target = target || "127.0.0.1";

        options = options || {};
        this.version = options.version
                ? options.version
                : Version1;

        if ( this.version == Version3 ) {
            this.user = authenticator;
        } else {
            this.community = authenticator || "public";
        }

        this.transport = options.transport
                ? options.transport
                : "udp4";
        this.port = options.port
                ? options.port
                : 161;
        this.trapPort = options.trapPort
                ? options.trapPort
                : 162;

        this.retries = (options.retries || options.retries == 0)
                ? options.retries
                : 1;
        this.timeout = options.timeout
                ? options.timeout
                : 5000;

        this.backoff = (options.backoff ?? 0) >= 1.0
                ? options.backoff
                : 1.0;

        this.sourceAddress = options.sourceAddress
                ? options.sourceAddress
                : undefined;
        this.sourcePort = options.sourcePort
                ? parseInt(options.sourcePort)
                : undefined;

        this.idBitsSize = options.idBitsSize
                ? parseInt(options.idBitsSize)
                : 32;

        this.context = options.context
                ? options.context
                : "";

        this.backwardsGetNexts = (typeof options.backwardsGetNexts !== 'undefined')
                ? options.backwardsGetNexts
                : true;

        this.reportOidMismatchErrors = (typeof options.reportOidMismatchErrors !== 'undefined')
                ? options.reportOidMismatchErrors
                : false;

        DEBUG = options.debug ?? false;

        this.engine = new Engine (options.engineID);
        this.reqs = {};
        this.reqCount = 0;

        this.dgram = createSocket (this.transport);
        this.dgram.unref();

        var me = this;
        this.dgram.on ("message", me.onMsg.bind (me));
        this.dgram.on ("close", me.onClose.bind (me));
        this.dgram.on ("error", me.onError.bind (me));

        if (this.sourceAddress || this.sourcePort)
            this.dgram.bind (this.sourcePort, this.sourceAddress);
    }

    close (): Session {
        this.dgram.close ();
        return this;
    }

    cancelRequests (error: Error): void {
        for (let id in this.reqs) {
            var req = this.reqs[id];
            this.unregisterRequest (req.getId ());
            req.responseCb (error);
        }
    }

    get (oids: Array<OID | string>, responseCb: (err: Error | null) => void): Session {
        const reportOidMismatchErrors = this.reportOidMismatchErrors;

        function feedCb (req: Req, message: Message): void {
            const pdu = message.pdu;
            const varbinds = new Array<Varbind>();

            if (req.message.pdu!.varbinds.length != pdu!.varbinds.length) {
                req.responseCb (new ResponseInvalidError ("Requested OIDs do not "
                        + "match response OIDs", ResponseInvalidCode.EReqResOidNoMatch));
            } else {
                for (let i = 0; i < req.message.pdu!.varbinds.length; i++) {
                    if ( reportOidMismatchErrors && req.message.pdu!.varbinds[i]!.oid != pdu!.varbinds[i]!.oid ) {
                        req.responseCb (new ResponseInvalidError ("OID '"
                                + req.message.pdu!.varbinds[i]!.oid
                                + "' in request at position '" + i + "' does not "
                                + "match OID '" + pdu!.varbinds[i]!.oid + "' in response "
                                + "at position '" + i + "'", ResponseInvalidCode.EReqResOidNoMatch));
                        return;
                    } else {
                        varbinds.push (pdu!.varbinds[i]!);
                    }
                }

                req.responseCb (null, varbinds);
            }
        }

        const pduVarbinds: Array<Varbind> = [];

        for (const oid of oids) {
            const varbind: Varbind = {
                "oid": oid
            };
            pduVarbinds.push (varbind);
        }

        this.simpleGet (GetRequestPdu, feedCb, pduVarbinds, responseCb);

        return this;
    }

    getBulk (oids: Array<OID | string>, nonRepeaters: number, maxRepetitions: number, responseCb: (err: Error | null) => void): Session;
    getBulk (oids: Array<OID | string>, nonRepeaters: number, responseCb: (err: Error | null) => void): Session;
    getBulk (oids: Array<OID | string>, responseCb: (err: Error | null) => void): Session;
    getBulk (): Session {
        let oids: Array<OID | string> = []
        let nonRepeaters: number = 0
        let maxRepetitions: number = 0
        let responseCb: ((err: Error | null) => void) = () => {}

	    const reportOidMismatchErrors = this.reportOidMismatchErrors;
	    const backwardsGetNexts = this.backwardsGetNexts;

        if (arguments.length >= 4) {
            oids = arguments[0];
            nonRepeaters = arguments[1];
            maxRepetitions = arguments[2];
            responseCb = arguments[3];
        } else if (arguments.length >= 3) {
            oids = arguments[0];
            nonRepeaters = arguments[1];
            maxRepetitions = 10;
            responseCb = arguments[2];
        } else {
            oids = arguments[0];
            nonRepeaters = 0;
            maxRepetitions = 10;
            responseCb = arguments[1];
        }

        function feedCb (req: Req, message: Message) {
            var pdu = message.pdu;
            var reqVarbinds = req.message.pdu!.varbinds;
            var varbinds: Array<Varbind | Array<Varbind>> = [];
            var i = 0;

            for ( ; i < reqVarbinds.length && i < pdu!.varbinds.length; i++) {
                if (isVarbindError (pdu!.varbinds[i]!)) {
                    if ( reportOidMismatchErrors && reqVarbinds[i]!.oid != pdu!.varbinds[i]!.oid ) {
                        req.responseCb (new ResponseInvalidError ("OID '" + reqVarbinds[i]!.oid
                                + "' in request at position '" + i + "' does not "
                                + "match OID '" + pdu!.varbinds[i]!.oid + "' in response "
                                + "at position '" + i + "'", ResponseInvalidCode.EReqResOidNoMatch));
                        return;
                    }
                } else {
                    if ( ! backwardsGetNexts && ! oidFollowsOid (reqVarbinds[i]!.oid as string, pdu!.varbinds[i]!.oid as string)) {
                        req.responseCb (new ResponseInvalidError ("OID '" + reqVarbinds[i]!.oid
                                + "' in request at positiion '" + i + "' does not "
                                + "precede OID '" + pdu!.varbinds[i]!.oid + "' in response "
                                + "at position '" + i + "'", ResponseInvalidCode.EOutOfOrder));
                        return;
                    }
                }
                if (i < nonRepeaters)
                    varbinds.push (pdu!.varbinds[i]!);
                else
                    varbinds.push ([pdu!.varbinds[i]!]);
            }

            var repeaters = reqVarbinds.length - nonRepeaters;

            for ( ; i < pdu!.varbinds.length; i++) {
                var reqIndex = (i - nonRepeaters) % repeaters + nonRepeaters;
                var prevIndex = i - repeaters;
                var prevOid = pdu!.varbinds[prevIndex]!.oid;

                if (isVarbindError (pdu!.varbinds[i]!)) {
                    if ( reportOidMismatchErrors && prevOid != pdu!.varbinds[i]!.oid ) {
                        req.responseCb (new ResponseInvalidError ("OID '" + prevOid
                                + "' in response at position '" + prevIndex + "' does not "
                                + "match OID '" + pdu!.varbinds[i]!.oid + "' in response "
                                + "at position '" + i + "'", ResponseInvalidCode.EReqResOidNoMatch));
                        return;
                    }
                } else {
                    if ( ! backwardsGetNexts && ! oidFollowsOid (prevOid as string, pdu!.varbinds[i]!.oid as string)) {
                        req.responseCb (new ResponseInvalidError ("OID '" + prevOid
                                + "' in response at positiion '" + prevIndex + "' does not "
                                + "precede OID '" + pdu!.varbinds[i]!.oid + "' in response "
                                + "at position '" + i + "'", ResponseInvalidCode.EOutOfOrder));
                        return;
                    }
                }
                (varbinds[reqIndex] as Array<Varbind>).push (pdu!.varbinds[i]!);
            }

            req.responseCb (null, varbinds);
        }

        var pduVarbinds: Array<Varbind> = [];

        for (var i = 0; i < oids.length; i++) {
            var varbind: Varbind = {
                oid: oids[i]!
            };
            pduVarbinds.push (varbind);
        }

        var options = {
            nonRepeaters: nonRepeaters,
            maxRepetitions: maxRepetitions
        };

        this.simpleGet (GetBulkRequestPdu, feedCb, pduVarbinds, responseCb,
                options);

        return this;
    }

    getNext (oids: Array<OID | string>, responseCb: (err: Error | null) => void): Session {
	    const backwardsGetNexts = this.backwardsGetNexts;

        function feedCb (req: Req, message: Message): void {
            var pdu = message.pdu;
            var varbinds: Array<Varbind> = [];

            if (req.message!.pdu!.varbinds.length != pdu!.varbinds.length) {
                req.responseCb (new ResponseInvalidError ("Requested OIDs do not "
                        + "match response OIDs", ResponseInvalidCode.EReqResOidNoMatch));
            } else {
                for (var i = 0; i < req.message.pdu!.varbinds.length; i++) {
                    if (isVarbindError (pdu!.varbinds[i]!)) {
                        varbinds.push (pdu!.varbinds[i]!);
                    } else if ( ! backwardsGetNexts && ! oidFollowsOid (req.message.pdu!.varbinds[i]!.oid as string,
                            pdu!.varbinds[i]!.oid as string)) {
                        req.responseCb (new ResponseInvalidError ("OID '"
                                + req.message.pdu!.varbinds[i]!.oid + "' in request at "
                                + "positiion '" + i + "' does not precede "
                                + "OID '" + pdu!.varbinds[i]!.oid + "' in response "
                                + "at position '" + i + "'", ResponseInvalidCode.EOutOfOrder));
                        return;
                    } else {
                        varbinds.push (pdu!.varbinds[i]!);
                    }
                }

                req.responseCb (null, varbinds);
            }
        }

        var pduVarbinds: Array<Varbind> = [];

        for (var i = 0; i < oids.length; i++) {
            var varbind: Varbind = {
                oid: oids[i]!
            };
            pduVarbinds.push (varbind);
        }

        this.simpleGet (GetNextRequestPdu, feedCb, pduVarbinds, responseCb);

        return this;
    }

    inform (typeOrOid: string | number, varbinds: Array<Varbind>, options: {port?: number; upTime?: number}, responseCb: (err: Error | null) => void): Session;
    inform (typeOrOid: string | number, varbinds: Array<Varbind>, responseCb: (err: Error | null) => void): Session;
    inform (typeOrOid: string | number, options: {port?: number; upTime?: number}, responseCb: (err: Error | null) => void): Session;
    inform (typeOrOid: string | number, responseCb: (err: Error | null) => void): Session;
    inform (): Session {
        let typeOrOid = arguments[0];
        let varbinds, responseCb;
        let options: {port?: number; upTime?: number} = {}

        /**
         ** Support the following signatures:
        **
        **    typeOrOid, varbinds, options, callback
        **    typeOrOid, varbinds, callback
        **    typeOrOid, options, callback
        **    typeOrOid, callback
        **/
        if (arguments.length >= 4) {
            varbinds = arguments[1];
            options = arguments[2];
            responseCb = arguments[3];
        } else if (arguments.length >= 3) {
            if (arguments[1].constructor != Array) {
                varbinds = [];
                options = arguments[1];
                responseCb = arguments[2];
            } else {
                varbinds = arguments[1];
                responseCb = arguments[2];
            }
        } else {
            varbinds = [];
            responseCb = arguments[1];
        }

        if ( this.version == Version1 ) {
            responseCb (new RequestInvalidError ("Inform not allowed for SNMPv1"));
            return this;
        }

        function feedCb (req: Req, message: Message) {
            const pdu = message.pdu;
            const varbinds: Array<Varbind> = [];

            if (req.message.pdu!.varbinds.length != pdu!.varbinds.length) {
                req.responseCb (new ResponseInvalidError ("Inform OIDs do not "
                        + "match response OIDs", ResponseInvalidCode.EReqResOidNoMatch));
            } else {
                for (let i = 0; i < req.message.pdu!.varbinds.length; i++) {
                    if (req.message.pdu!.varbinds[i]!.oid != pdu!.varbinds[i]!.oid) {
                        req.responseCb (new ResponseInvalidError ("OID '"
                                + req.message.pdu!.varbinds[i]!.oid
                                + "' in inform at positiion '" + i + "' does not "
                                + "match OID '" + pdu!.varbinds[i]!.oid + "' in response "
                                + "at position '" + i + "'", ResponseInvalidCode.EReqResOidNoMatch));
                        return;
                    } else {
                        varbinds.push (pdu!.varbinds[i]!);
                    }
                }

                req.responseCb (null, varbinds);
            }
        }

        if (typeof typeOrOid != "string")
            typeOrOid = "1.3.6.1.6.3.1.1.5." + (typeOrOid + 1);

        const pduVarbinds = [
            {
                oid: "1.3.6.1.2.1.1.3.0",
                type: ObjectType.TimeTicks,
                value: options.upTime || Math.floor (process.uptime () * 100)
            },
            {
                oid: "1.3.6.1.6.3.1.1.4.1.0",
                type: ObjectType.OID,
                value: typeOrOid
            }
        ];

        for (let i = 0; i < varbinds.length; i++) {
            const varbind = {
                oid: varbinds[i].oid,
                type: varbinds[i].type,
                value: varbinds[i].value
            };
            pduVarbinds.push (varbind);
        }

        options.port = this.trapPort;

        this.simpleGet (InformRequestPdu, feedCb, pduVarbinds, responseCb, options);

        return this;
    }

    onClose (): void {
        this.cancelRequests (new Error ("Socket forcibly closed"));
        this.emit ("close");
    }

    onError (error: Error): void {
	    this.emit ("error", error);
    }

    onMsg (buffer: Buffer): void {
        try {
            var message = Message.createFromBuffer (buffer);
        } catch (error) {
            this.emit("error", error);
            return;
        }

        const req = this.unregisterRequest (message.getReqId ());
        if ( ! req )
            return;

        if ( ! message.processIncomingSecurity (this.user, req.responseCb) )
            return;

        if (message.version != req.message.version) {
            req.responseCb (new ResponseInvalidError ("Version in request '"
                    + req.message.version + "' does not match version in "
                    + "response '" + message.version + "'", ResponseInvalidCode.EVersionNoMatch));
        } else if (message.community != req.message.community) {
            req.responseCb (new ResponseInvalidError ("Community '"
                    + req.message.community + "' in request does not match "
                    + "community '" + message.community + "' in response", ResponseInvalidCode.ECommunityNoMatch));
        } else if (message.pdu!.type == PduType.Report) {
            this.msgSecurityParameters = {
                msgAuthoritativeEngineID: message.msgSecurityParameters.msgAuthoritativeEngineID,
                msgAuthoritativeEngineBoots: message.msgSecurityParameters.msgAuthoritativeEngineBoots,
                msgAuthoritativeEngineTime: message.msgSecurityParameters.msgAuthoritativeEngineTime
            };
            if ( this.proxy ) {
                this.msgSecurityParameters.msgUserName = this.proxy.user.name;
                this.msgSecurityParameters.msgAuthenticationParameters = "";
                this.msgSecurityParameters.msgPrivacyParameters = "";
            } else {
                if ( ! req.originalPdu || ! req.allowReport ) {
                    if (Array.isArray(message.pdu.varbinds) && message.pdu.varbinds[0] && message.pdu.varbinds[0].oid.indexOf(UsmStatsBase) === 0) {
                        this.userSecurityModelError (req, message.pdu.varbinds[0].oid);
                        return;
                    }
                    req.responseCb (new ResponseInvalidError ("Unexpected Report PDU", ResponseInvalidCode.EUnexpectedReport) );
                    return;
                }
                req.originalPdu.contextName = this.context;
                var timeSyncNeeded = ! message.msgSecurityParameters.msgAuthoritativeEngineBoots && ! message.msgSecurityParameters.msgAuthoritativeEngineTime;
                this.sendV3Req (req.originalPdu, req.feedCb, req.responseCb, req.options, req.port, timeSyncNeeded);
            }
        } else if ( this.proxy ) {
            this.onProxyResponse (req, message);
        } else if (message.pdu.type == PduType.GetResponse) {
            req.onResponse (req, message);
        } else {
            req.responseCb (new ResponseInvalidError ("Unknown PDU type '"
                    + message.pdu.type + "' in response", ResponseInvalidCode.EUnknownPduType));
        }
    }

    onSimpleGetResponse (req: Req, message: Message) {
        const pdu = message.pdu as SimpleResponsePdu;

        if (pdu.errorStatus > 0) {
            const statusString = ErrorStatus[pdu.errorStatus]
                    || ErrorStatus.GeneralError;
            const statusCode = ErrorStatus[statusString]
                    || ErrorStatus[ErrorStatus.GeneralError];

            if (pdu.errorIndex <= 0 || pdu.errorIndex > pdu.varbinds.length) {
                req.responseCb (new RequestFailedError (statusString, statusCode as ErrorStatusKey));
            } else {
                var oid = pdu.varbinds[pdu.errorIndex - 1]!.oid;
                var error = new RequestFailedError (statusString + ": " + oid,
                        statusCode as ErrorStatusKey);
                req.responseCb (error);
            }
        } else {
            req.feedCb (req, message);
        }
    }

    registerRequest (req: Req): void {
        if (! this.reqs[req.getId ()]) {
            this.reqs[req.getId ()] = req;
            if (this.reqCount <= 0)
                this.dgram.ref();
            this.reqCount++;
        }
        const me = this;
        req.timer = setTimeout (function () {
            if (req.retries-- > 0) {
                me.send (req);
            } else {
                me.unregisterRequest (req.getId ());
                req.responseCb (new RequestTimedOutError (
                        "Request timed out"));
            }
        }, req.timeout);
        // Apply timeout backoff
        if (req.backoff && req.backoff >= 1)
            req.timeout *= req.backoff;
    }

    send (req: Req, noWait?: boolean): Session {
        try {
            var me = this;

            var buffer = req.message.toBuffer ();

            this.dgram.send (buffer, 0, buffer.length, req.port, this.target,
                    function (error, bytes) {
                if (error) {
                    req.responseCb (error);
                } else {
                    if (noWait) {
                        req.responseCb (null);
                    } else {
                        me.registerRequest (req);
                    }
                }
            });
        } catch (error) {
            req.responseCb (error as Error);
        }

        return this;
    }

    set (varbinds: Array<Varbind>, responseCb: (err: Error) => void): Session {
        const reportOidMismatchErrors = this.reportOidMismatchErrors;

        function feedCb (req: Req, message: Message): void {
            const pdu = message.pdu!;
            const varbinds: Array<Varbind> = [];

            if (req.message.pdu!.varbinds.length != pdu.varbinds.length) {
                req.responseCb (new ResponseInvalidError ("Requested OIDs do not "
                        + "match response OIDs", ResponseInvalidCode.EReqResOidNoMatch));
            } else {
                for (let i = 0; i < req.message.pdu!.varbinds.length; i++) {
                    if ( reportOidMismatchErrors && req.message.pdu!.varbinds[i]!.oid != pdu.varbinds[i]!.oid ) {
                        req.responseCb (new ResponseInvalidError ("OID '"
                                + req.message.pdu!.varbinds[i]!.oid
                                + "' in request at position '" + i + "' does not "
                                + "match OID '" + pdu.varbinds[i]!.oid + "' in response "
                                + "at position '" + i + "'", ResponseInvalidCode.EReqResOidNoMatch));
                        return;
                    } else {
                        varbinds.push (pdu.varbinds[i]!);
                    }
                }

                req.responseCb (null, varbinds);
            }
        }

        const pduVarbinds = [];

        for (let i = 0; i < varbinds.length; i++) {
            const varbind = {
                oid: varbinds[i]!.oid,
                type: varbinds[i]!.type,
                value: varbinds[i]!.value
            };
            pduVarbinds.push (varbind);
        }

        this.simpleGet (SetRequestPdu, feedCb, pduVarbinds, responseCb);

        return this;
    }

    simpleGet<T extends SimplePdu> (pduClass: new(id?: number, varbinds?: Array<Varbind>, options?: SimplePduOptions) => T, feedCb: (req: Req, msg: Message) => void, varbinds: Array<Varbind>,
		responseCb: (error: Error | null, varbinds?: Array<Varbind>) => void, options?: ReqOptions & SimplePduOptions) {
        var id = _generateId (this.idBitsSize);
        options = Object.assign({}, options, { context: this.context });
        var pdu = SimplePdu.createFromVariables (pduClass, id, varbinds, options);
        var message;
        var req;

        if ( this.version == Version3 ) {
            if ( this.msgSecurityParameters ) {
                this.sendV3Req (pdu, feedCb, responseCb, options, this.port, true);
            } else {
                this.sendV3Discovery (pdu, feedCb, responseCb, options);
            }
        } else {
            message = Message.createCommunity (this.version, this.community!, pdu);
            req = new Req (this, message, feedCb, responseCb, options);
            this.send (req);
        }
    }

    private static subtreeCb (req: Req, varbinds: Array<Varbind>): boolean {
        let done = false;

        for (let i = varbinds.length; i > 0; i--) {
            if (! oidInSubtree (req.baseOid, varbinds[i - 1]!.oid)) {
                done = true;
                varbinds.pop ();
            }
        }

        if (varbinds.length > 0) {
            if (req.feedCb (varbinds)) {
                done = false;
            }
        }

        return done
    }

    subtree () {
        const me = this;
        const oid = arguments[0];
        let maxRepetitions, feedCb, doneCb;

        if (arguments.length < 4) {
            maxRepetitions = 20;
            feedCb = arguments[1];
            doneCb = arguments[2];
        } else {
            maxRepetitions = arguments[1];
            feedCb = arguments[2];
            doneCb = arguments[3];
        }

        const req = {
            feedCb: feedCb,
            doneCb: doneCb,
            maxRepetitions: maxRepetitions,
            baseOid: oid
        };

        this.walk (oid, maxRepetitions, subtreeCb.bind (me, req), doneCb);

        return this;
    }

    private static tableColumnsResponseCb (req, error) {
        if (error) {
            req.responseCb (error);
        } else if (req.error) {
            req.responseCb (req.error);
        } else {
            if (req.columns.length > 0) {
                const column = req.columns.pop ();
                const me = this;
                this.subtree (req.rowOid + column, req.maxRepetitions,
                        tableColumnsFeedCb.bind (me, req),
                        tableColumnsResponseCb.bind (me, req));
            } else {
                req.responseCb (null, req.table);
            }
        }
    }

    private static tableColumnsFeedCb (req, varbinds) {
        for (let i = 0; i < varbinds.length; i++) {
            if (isVarbindError (varbinds[i])) {
                req.error = new RequestFailedError (varbindError (varbinds[i]));
                return true;
            }

            var oid = varbinds[i].oid.replace (req.rowOid, "");
            if (oid && oid != varbinds[i].oid) {
                const match = oid.match (/^(\d+)\.(.+)$/);
                if (match && match[1] > 0) {
                    if (! req.table[match[2]])
                        req.table[match[2]] = {};
                    req.table[match[2]][match[1]] = varbinds[i].value;
                }
            }
        }
    }

    tableColumns = function () {
        const me = this;

        const oid = arguments[0];
        const columns = arguments[1];
        let maxRepetitions, responseCb;

        if (arguments.length < 4) {
            responseCb = arguments[2];
            maxRepetitions = 20;
        } else {
            maxRepetitions = arguments[2];
            responseCb = arguments[3];
        }

        const req = {
            responseCb: responseCb,
            maxRepetitions: maxRepetitions,
            baseOid: oid,
            rowOid: oid + ".1.",
            columns: columns.slice(0),
            table: {}
        };

        if (req.columns.length > 0) {
            const column = req.columns.pop ();
            this.subtree (req.rowOid + column, maxRepetitions,
                    tableColumnsFeedCb.bind (me, req),
                    tableColumnsResponseCb.bind (me, req));
        }

        return this;
    }

    private static tableResponseCb (req, error) {
        if (error)
            req.responseCb (error);
        else if (req.error)
            req.responseCb (req.error);
        else
            req.responseCb (null, req.table);
    }

    private static tableFeedCb (req, varbinds) {
        for (let i = 0; i < varbinds.length; i++) {
            if (isVarbindError (varbinds[i])) {
                req.error = new RequestFailedError (varbindError (varbinds[i]));
                return true;
            }

            const oid = varbinds[i].oid.replace (req.rowOid, "");
            if (oid && oid != varbinds[i].oid) {
                const match = oid.match (/^(\d+)\.(.+)$/);
                if (match && match[1] > 0) {
                    if (! req.table[match[2]])
                        req.table[match[2]] = {};
                    req.table[match[2]][match[1]] = varbinds[i].value;
                }
            }
        }
    }

    table () {
        const me = this;

        const oid = arguments[0];
        let maxRepetitions, responseCb;

        if (arguments.length < 3) {
            responseCb = arguments[1];
            maxRepetitions = 20;
        } else {
            maxRepetitions = arguments[1];
            responseCb = arguments[2];
        }

        const req = {
            responseCb: responseCb,
            maxRepetitions: maxRepetitions,
            baseOid: oid,
            rowOid: oid + ".1.",
            table: {}
        };

        this.subtree (oid, maxRepetitions, tableFeedCb.bind (me, req),
                tableResponseCb.bind (me, req));

        return this;
    }

    trap () {
        const req = {};

        const typeOrOid = arguments[0];
        let varbinds, options = {}, responseCb;
        let message;

        /**
         ** Support the following signatures:
            **
            **    typeOrOid, varbinds, options, callback
            **    typeOrOid, varbinds, agentAddr, callback
            **    typeOrOid, varbinds, callback
            **    typeOrOid, agentAddr, callback
            **    typeOrOid, options, callback
            **    typeOrOid, callback
            **/
        if (arguments.length >= 4) {
            varbinds = arguments[1];
            if (typeof arguments[2] == "string") {
                options.agentAddr = arguments[2];
            } else if (arguments[2].constructor != Array) {
                options = arguments[2];
            }
            responseCb = arguments[3];
        } else if (arguments.length >= 3) {
            if (typeof arguments[1] == "string") {
                varbinds = [];
                options.agentAddr = arguments[1];
            } else if (arguments[1].constructor != Array) {
                varbinds = [];
                options = arguments[1];
            } else {
                varbinds = arguments[1];
                options.agentAddr = null;
            }
            responseCb = arguments[2];
        } else {
            varbinds = [];
            responseCb = arguments[1];
        }

        let pdu;
        const pduVarbinds = [];

        for (let i = 0; i < varbinds.length; i++) {
            const varbind = {
                oid: varbinds[i].oid,
                type: varbinds[i].type,
                value: varbinds[i].value
            };
            pduVarbinds.push (varbind);
        }

        const id = _generateId (this.idBitsSize);

        if (this.version == Version2c || this.version == Version3 ) {
            if (typeof typeOrOid != "string")
                typeOrOid = "1.3.6.1.6.3.1.1.5." + (typeOrOid + 1);

            pduVarbinds.unshift (
                {
                    oid: "1.3.6.1.2.1.1.3.0",
                    type: ObjectType.TimeTicks,
                    value: options.upTime || Math.floor (process.uptime () * 100)
                },
                {
                    oid: "1.3.6.1.6.3.1.1.4.1.0",
                    type: ObjectType.OID,
                    value: typeOrOid
                }
            );

            pdu = TrapV2Pdu.createFromVariables (id, pduVarbinds, options);
        } else {
            pdu = TrapPdu.createFromVariables (typeOrOid, pduVarbinds, options);
        }

        if ( this.version == Version3 ) {
            var msgSecurityParameters = {
                msgAuthoritativeEngineID: this.engine.engineID,
                msgAuthoritativeEngineBoots: 0,
                msgAuthoritativeEngineTime: 0
            };
            message = Message.createRequestV3 (this.user, msgSecurityParameters, pdu);
        } else {
            message = Message.createCommunity (this.version, this.community, pdu);
        }

        req = {
            id: id,
            message: message,
            responseCb: responseCb,
            port: this.trapPort
        };

        this.send (req, true);

        return this;
    }

    unregisterRequest (id: number) {
        const req = this.reqs[id];
        if (req) {
            delete this.reqs[id];
            clearTimeout (req.timer);
            delete req.timer;
            this.reqCount--;
            if (this.reqCount <= 0)
                this.dgram.unref();
            return req;
        } else {
            return null;
        }
    }

    private static walkCb (req, error, varbinds) {
        var done = 0;
        var oid;

        if (error) {
            if (error instanceof RequestFailedError) {
                if (error.status != ErrorStatus.NoSuchName) {
                    req.doneCb (error);
                    return;
                } else {
                    // signal the version 1 walk code below that it should stop
                    done = 1;
                }
            } else {
                req.doneCb (error);
                return;
            }
        }

        if ( ! varbinds || ! varbinds.length ) {
            req.doneCb(null);
            return;
        }

        if (this.version == Version2c || this.version == Version3) {
            for (var i = varbinds[0].length; i > 0; i--) {
                if (varbinds[0][i - 1].type == ObjectType.EndOfMibView) {
                    varbinds[0].pop ();
                    done = 1;
                }
            }
            if (req.feedCb (varbinds[0]))
                done = 1;
            if (! done)
                oid = varbinds[0][varbinds[0].length - 1].oid;
        } else {
            if (! done) {
                if (req.feedCb (varbinds)) {
                    done = 1;
                } else {
                    oid = varbinds[0].oid;
                }
            }
        }

        if (done)
            req.doneCb (null);
        else
            this.walk (oid, req.maxRepetitions, req.feedCb, req.doneCb,
                    req.baseOid);
    }

    walk  = function () {
        const me = this;
        const oid = arguments[0];
        let maxRepetitions, feedCb, doneCb;

        if (arguments.length < 4) {
            maxRepetitions = 20;
            feedCb = arguments[1];
            doneCb = arguments[2];
        } else {
            maxRepetitions = arguments[1];
            feedCb = arguments[2];
            doneCb = arguments[3];
        }

        const req = {
            maxRepetitions: maxRepetitions,
            feedCb: feedCb,
            doneCb: doneCb
        };

        if (this.version == Version2c || this.version == Version3)
            this.getBulk ([oid], 0, maxRepetitions,
                    walkCb.bind (me, req));
        else
            this.getNext ([oid], walkCb.bind (me, req));

        return this;
    }

    sendV3Req (pdu, feedCb, responseCb, options, port, allowReport) {
        const message = Message.createRequestV3 (this.user, this.msgSecurityParameters, pdu);
        const reqOptions = options || {};
        const req = new Req (this, message, feedCb, responseCb, reqOptions);
        req.port = port;
        req.originalPdu = pdu;
        req.allowReport = allowReport;
        this.send (req);
    }

    sendV3Discovery (originalPdu, feedCb, responseCb, options) {
        const discoveryPdu = createDiscoveryPdu(this.context);
        const discoveryMessage = Message.createDiscoveryV3 (discoveryPdu);
        const discoveryReq = new Req (this, discoveryMessage, feedCb, responseCb, options);
        discoveryReq.originalPdu = originalPdu;
        discoveryReq.allowReport = true;
        this.send (discoveryReq);
    }

    userSecurityModelError (req, oid) {
        const oidSuffix = oid.replace (UsmStatsBase + '.', '').replace (/\.0$/, '');
        const errorType = UsmStats[oidSuffix] || "Unexpected Report PDU";
        req.responseCb (new ResponseInvalidError (errorType, ResponseInvalidCode.EAuthFailure) );
    }

    onProxyResponse (req, message) {
        if ( message.version != Version3 ) {
            this.callback (new RequestFailedError ("Only SNMP version 3 contexts are supported"));
            return;
        }
        message.pdu.contextName = this.proxy.context;
        message.user = req.proxiedUser;
        message.setAuthentication ( ! (req.proxiedUser.level == SecurityLevel.noAuthNoPriv));
        message.setPrivacy (req.proxiedUser.level == SecurityLevel.authPriv);
        message.msgSecurityParameters = {
            msgAuthoritativeEngineID: req.proxiedEngine.engineID,
            msgAuthoritativeEngineBoots: req.proxiedEngine.engineBoots,
            msgAuthoritativeEngineTime: req.proxiedEngine.engineTime,
            msgUserName: req.proxiedUser.name,
            msgAuthenticationParameters: "",
            msgPrivacyParameters: ""
        };
        message.buffer = null;
        message.pdu.contextEngineID = message.msgSecurityParameters.msgAuthoritativeEngineID;
        message.pdu.contextName = this.proxy.context;
        message.pdu.id = req.proxiedPduId;
        this.proxy.listener.send (message, req.proxiedRinfo);
    }

    static create (target, community, options) {
        // Ensure that options may be optional
        const version = (options && options.version) ? options.version : Version1;
        if (version != Version1 && version != Version2c) {
            throw new ResponseInvalidError ("SNMP community session requested but version '" + options.version + "' specified in options not valid",
                    ResponseInvalidCode.EVersionNoMatch);
        } else {
            if (!options)
                options = {};
            options.version = version;
            return new Session (target, community, options);
        }
    }

    static createV3 (target, user, options) {
        // Ensure that options may be optional
        if ( options && options.version && options.version != Version3 ) {
            throw new ResponseInvalidError ("SNMPv3 session requested but version '" + options.version + "' specified in options",
                    ResponseInvalidCode.EVersionNoMatch);
        } else {
            if (!options)
                options = {};
            options.version = Version3;
        }
        return new Session (target, user, options);
    }
}

class Engine
{
    engineID: Buffer;
    engineBoots: number;
    engineTime: number;

    constructor (engineID?: string | Buffer, engineBoots?: number, engineTime?: number) {
        this.engineID = {} as Buffer
        if ( engineID ) {
            if ( ! (engineID instanceof Buffer) ) {
                engineID = engineID.replace('0x', '');
                this.engineID = Buffer.from((engineID.toString().length % 2 == 1 ? '0' : '') + engineID.toString(), 'hex');
            } else {
                this.engineID = engineID;
            }
        } else {
            this.generateEngineID ();
        }
        this.engineBoots = 0;
        this.engineTime = 10;
    }

    private generateEngineID (): void {
        // generate a 17-byte engine ID in the following format:
        // 0x80 | 0x00B983 (enterprise OID) | 0x80 (enterprise-specific format) | 12 bytes of random
        this.engineID = Buffer.alloc (17);
        this.engineID.fill ('8000B98380', 'hex', 0, 5);
        this.engineID.fill (randomBytes (12), 5, 17, 'hex');
    }
}

class Listener
{
    constructor (options, receiver) {
        this.receiver = receiver;
        this.callback = receiver.onMsg;
        this.family = options.transport || 'udp4';
        this.port = options.port || 161;
        this.address = options.address;
        this.disableAuthorization = options.disableAuthorization || false;
    }

    startListening () {
        const me = this;
        this.dgram = createSocket (this.family);
        this.dgram.on ("error", me.receiver.callback);
        this.dgram.bind (this.port, this.address);
        this.dgram.on ("message", me.callback.bind (me.receiver));
    }

    send (message, rinfo) {
	    // var me = this;

        const buffer = message.toBuffer ();

        this.dgram.send (buffer, 0, buffer.length, rinfo.port, rinfo.address,
                function (error, bytes) {
            if (error) {
                // me.callback (error);
                console.error ("Error sending: " + error.message);
            } else {
                // debug ("Listener sent response message");
            }
        });
    }

    static formatCallbackData (pdu, rinfo) {
        if ( pdu.contextEngineID ) {
            pdu.contextEngineID = pdu.contextEngineID.toString('hex');
        }
        delete pdu.nonRepeaters;
        delete pdu.maxRepetitions;
        return {
            pdu: pdu,
            rinfo: rinfo
        };
    }

    static processIncoming (buffer, authorizer, callback): Message | undefined {
        const message = Message.createFromBuffer (buffer);
        let community;

        // Authorization
        if ( message.version == Version3 ) {
            message.user = authorizer.users.filter( localUser => localUser.name ==
                    message.msgSecurityParameters.msgUserName )[0];
            message.disableAuthentication = authorizer.disableAuthorization;
            if ( ! message.user ) {
                if ( message.msgSecurityParameters.msgUserName != "" && ! authorizer.disableAuthorization ) {
                    callback (new RequestFailedError ("Local user not found for message with user " +
                            message.msgSecurityParameters.msgUserName));
                    return;
                } else if ( message.hasAuthentication () ) {
                    callback (new RequestFailedError ("Local user not found and message requires authentication with user " +
                            message.msgSecurityParameters.msgUserName));
                    return;
                } else {
                    message.user = {
                        name: "",
                        level: SecurityLevel.noAuthNoPriv
                    };
                }
            }
            if ( (message.user.level == SecurityLevel.authNoPriv || message.user.level == SecurityLevel.authPriv) && ! message.hasAuthentication() ) {
                callback (new RequestFailedError ("Local user " + message.msgSecurityParameters.msgUserName +
                        " requires authentication but message does not provide it"));
                return;
            }
            if ( message.user.level == SecurityLevel.authPriv && ! message.hasPrivacy() ) {
                callback (new RequestFailedError ("Local user " + message.msgSecurityParameters.msgUserName +
                        " requires privacy but message does not provide it"));
                return;
            }
            if ( ! message.processIncomingSecurity (message.user, callback) ) {
                return;
            }
        } else {
            community = authorizer.communities.filter( localCommunity => localCommunity == message.community )[0];
            if ( ! community && ! authorizer.disableAuthorization ) {
                callback (new RequestFailedError ("Local community not found for message with community " + message.community));
                return;
            }
        }

        return message;
    }

    close () {
        if ( this.dgram ) {
            this.dgram.close ();
        }
    }
}

type AuthorizerOptions = {
    disableAuthorization?: boolean;
    accessControlModelType?: number;
}

type AuthorizerCommunity = string
type AuthorizerUser = {
    name: string
}

class Authorizer
{
    communities: Array<AuthorizerCommunity>;
    users: Array<AuthorizerUser>;
    disableAuthorization: boolean;
    accessControlModelType: number;
    accessControlModel?: null | SimpleAccessControlModel;

    constructor (options: AuthorizerOptions) {
        this.communities = [];
        this.users = [];
        this.disableAuthorization = options.disableAuthorization ?? false;
        this.accessControlModelType = options.accessControlModelType || AccessControlModelType.None;

        if ( this.accessControlModelType == AccessControlModelType.None ) {
            this.accessControlModel = null;
        } else if ( this.accessControlModelType == AccessControlModelType.Simple ) {
            this.accessControlModel = new SimpleAccessControlModel ();
        }
    }

    addCommunity (community: AuthorizerCommunity): void {
        if ( this.getCommunity (community) ) {
            return;
        } else {
            this.communities.push (community);
            if ( this.accessControlModelType == AccessControlModelType.Simple ) {
                this.accessControlModel!.setCommunityAccess (community, AccessLevel.ReadOnly);
            }
        }
    }

    getCommunity (community: AuthorizerCommunity): AuthorizerCommunity | null {
	    return this.communities.filter( localCommunity => localCommunity == community )[0] || null;
    };

    getCommunities (): Array<AuthorizerCommunity> {
	    return this.communities;
    };

    deleteCommunity (community: AuthorizerCommunity): void {
	    const index = this.communities.indexOf(community);
	    if ( index > -1 ) {
    		this.communities.splice(index, 1);
	    }
    }

    addUser (user: AuthorizerUser): void {
        if ( this.getUser (user.name) ) {
            this.deleteUser (user.name);
        }
        this.users.push (user);
        if ( this.accessControlModelType == AccessControlModelType.Simple ) {
            this.accessControlModel!.setUserAccess (user.name, AccessLevel.ReadOnly);
        }
    }

    getUser (userName: string): AuthorizerUser | null {
	    return this.users.filter( localUser => localUser.name == userName )[0] || null;
    }

    getUsers (): Array<AuthorizerUser> {
	    return this.users;
    }

    deleteUser (userName: string): void {
        const index = this.users.findIndex(localUser => localUser.name == userName );
        if ( index > -1 ) {
            this.users.splice(index, 1);
        }
    }

    getAccessControlModelType (): number {
        return this.accessControlModelType;
    }

    getAccessControlModel (): SimpleAccessControlModel | null | undefined {
	    return this.accessControlModel;
    }

    isAccessAllowed (securityModel, securityName, pduType) {
        if ( this.accessControlModel ) {
            return this.accessControlModel.isAccessAllowed (securityModel, securityName, pduType);
        } else {
            return true;
        }
    }
}

type CommunityAccess = {
    community: AuthorizerCommunity;
    level: AccessLevelType;
}

type UserAccess = {
    userName: string;
    level: AccessLevelType;
}

class SimpleAccessControlModel
{
    communitiesAccess: Array<CommunityAccess>
    usersAccess: Array<UserAccess>

    constructor () {
        this.communitiesAccess = [];
        this.usersAccess = [];
    }

    getCommunityAccess (community: AuthorizerCommunity): CommunityAccess | undefined {
	    return this.communitiesAccess.find (entry => entry.community == community );
    }

    getCommunityAccessLevel (community: AuthorizerCommunity): AccessLevelType {
	    const communityAccessEntry = this.getCommunityAccess (community);
	    return communityAccessEntry ? communityAccessEntry.level : AccessLevel.None;
    }

    getCommunitiesAccess (): Array<CommunityAccess> {
	    return this.communitiesAccess;
    }

    setCommunityAccess (community: AuthorizerCommunity, accessLevel: AccessLevelType): void {
        let accessEntry = this.getCommunityAccess (community);
        if ( accessEntry ) {
            accessEntry.level = accessLevel;
        } else {
            this.communitiesAccess.push ({
                community: community,
                level: accessLevel
            });
            this.communitiesAccess.sort ((a, b) => (a.community > b.community) ? 1 : -1);
        }
    }

    removeCommunityAccess (community: AuthorizerCommunity): void {
	    this.communitiesAccess.splice ( this.communitiesAccess.findIndex (entry => entry.community == community), 1);
    }

    getUserAccess (userName: string): UserAccess | undefined {
	    return this.usersAccess.find (entry => entry.userName == userName );
    }

    getUserAccessLevel (user: string): AccessLevelType {
	    const userAccessEntry = this.getUserAccess (user);
	    return userAccessEntry ? userAccessEntry.level : AccessLevel.None;
    }

    getUsersAccess (): Array<UserAccess> {
	    return this.usersAccess;
    }

    setUserAccess (userName: string, accessLevel: AccessLevelType): void {
        let accessEntry = this.getUserAccess (userName);
        if ( accessEntry ) {
            accessEntry.level = accessLevel;
        } else {
            this.usersAccess.push ({
                userName: userName,
                level: accessLevel
            });
            this.usersAccess.sort ((a, b) => (a.userName > b.userName) ? 1 : -1);
        }
    }

    removeUserAccess (userName: string): void {
	    this.usersAccess.splice ( this.usersAccess.findIndex (entry => entry.userName == userName), 1);
    }

    isAccessAllowed (securityModel: SecurityModel, securityName: AuthorizerCommunity, pduType: PduTypeKey): boolean {
	    let accessLevelConfigured;
	    let accessLevelRequired;

        switch ( securityModel ) {
            case Version1:
            case Version2c:
                accessLevelConfigured = this.getCommunityAccessLevel (securityName);
                break;
            case Version3:
                accessLevelConfigured = this.getUserAccessLevel (securityName);
                break;
        }
        switch ( pduType ) {
            case PduType.SetRequest:
                accessLevelRequired = AccessLevel.ReadWrite;
                break;
            case PduType.GetRequest:
            case PduType.GetNextRequest:
            case PduType.GetBulkRequest:
                accessLevelRequired = AccessLevel.ReadOnly;
                break;
            default:
                accessLevelRequired = AccessLevel.None;
                break;
        }
        switch ( accessLevelRequired ) {
            case AccessLevel.ReadWrite:
                return accessLevelConfigured == AccessLevel.ReadWrite;
            case AccessLevel.ReadOnly:
                return accessLevelConfigured == AccessLevel.ReadWrite || accessLevelConfigured == AccessLevel.ReadOnly;
            case AccessLevel.None:
                return true;
            default:
                return false;
        }
    }
}


/*****************************************************************************
 ** Receiver class definition
 **/

type ReceiverOptions = AuthorizerOptions & {
    debug?: boolean;
    port?: number;
    transport?: string;
    engineID?: string | Buffer;
    includeAuthentication?: boolean;
    disableAuthorization?: boolean;
    context?: string;
}

type ReceiverCallback = (err: Error | null, data: ) => void;

export class Receiver
{
    listener: Listener;
    authorizer: Authorizer;
    engine: Engine;
    engineBoots: number;
    engineTime: number;
    disableAuthorization: boolean;
    callback: ReceiverCallback;
    family: string;
    port: number;
    includeAuthentication: boolean;
    context: string;

    constructor (options: ReceiverOptions, callback: ReceiverCallback) {
        DEBUG = options.debug ?? false;
        this.listener = new Listener (options, this);
        this.authorizer = new Authorizer (options);
        this.engine = new Engine (options.engineID);

        this.engineBoots = 0;
        this.engineTime = 10;
        this.disableAuthorization = false;

        this.callback = callback;
        this.family = options.transport || 'udp4';
        this.port = options.port || 162;
        options.port = this.port;
        this.disableAuthorization = options.disableAuthorization || false;
        this.includeAuthentication = options.includeAuthentication || false;
        this.context = (options && options.context) ? options.context : "";
        this.listener = new Listener (options, this);
    }

    getAuthorizer (): Authorizer {
	    return this.authorizer;
    }

    onMsg (buffer, rinfo) {

        let message: Message | undefined = undefined;

        try {
            message = Listener.processIncoming (buffer, this.authorizer, this.callback);
        } catch (error) {
            this.callback (new ProcessingError ("Failure to process incoming message", error as Error, rinfo, buffer));
            return;
        }

        if ( ! message ) {
            return;
        }

        // The only GetRequest PDUs supported are those used for SNMPv3 discovery
        if ( message.pdu.type == PduType.GetRequest ) {
            if ( message.version != Version3 ) {
                this.callback (new RequestInvalidError ("Only SNMPv3 discovery GetRequests are supported"));
                return;
            } else if ( message.hasAuthentication() ) {
                this.callback (new RequestInvalidError ("Only discovery (noAuthNoPriv) GetRequests are supported but this message has authentication"));
                return;
            } else if ( ! message.isReportable () ) {
                this.callback (new RequestInvalidError ("Only discovery GetRequests are supported and this message does not have the reportable flag set"));
                return;
            }
            let reportMessage = message.createReportResponseMessage (this.engine, this.context);
            this.listener.send (reportMessage, rinfo);
            return;
        }

        // Inform/trap processing
        // debug (JSON.stringify (message.pdu, null, 2));
        if ( message.pdu.type == PduType.Trap || message.pdu.type == PduType.TrapV2 ) {
            this.callback (null, this.formatCallbackData (message, rinfo) );
        } else if ( message.pdu.type == PduType.InformRequest ) {
            message.pdu.type = PduType.GetResponse;
            message.buffer = null;
            message.setReportable (false);
            this.listener.send (message, rinfo);
            message.pdu.type = PduType.InformRequest;
            this.callback (null, this.formatCallbackData (message, rinfo) );
        } else {
            this.callback (new RequestInvalidError ("Unexpected PDU type " + message.pdu.type + " (" + PduType[message.pdu.type] + ")"));
        }
    }

    formatCallbackData (message, rinfo) {
        if ( message.pdu.contextEngineID ) {
            message.pdu.contextEngineID = message.pdu.contextEngineID.toString('hex');
        }
        delete message.pdu.nonRepeaters;
        delete message.pdu.maxRepetitions;
        const formattedData = {
            pdu: message.pdu,
            rinfo: rinfo
        };
        if (this.includeAuthentication) {
            if (message.community) {
                formattedData.pdu.community = message.community;
            } else if (message.user) {
                formattedData.pdu.user = message.user.name;
            }
        }

        return formattedData;
    }

    close () {
	    this.listener.close ();
    }

    create (options, callback) {
        const receiver = new Receiver (options, callback);
        receiver.listener.startListening ();
        return receiver;
    }
}

export class ModuleStore
{
    constructor () {
        this.parser = mibparser ();
        this.translations = {
            oidToPath: {},
            oidToModule: {},
            pathToOid: {},
            pathToModule: {},
            moduleToOid: {},
            moduleToPath: {}
        };
    }

    getSyntaxTypes () {
        const syntaxTypes = {};
        Object.assign (syntaxTypes, ObjectType);
        var entryArray;

        for ( var mibModule of Object.values (this.parser.Modules) ) {
            entryArray = Object.values (mibModule);
            for ( var mibEntry of entryArray ) {
                if ( mibEntry.MACRO == "TEXTUAL-CONVENTION" ) {
                    if ( mibEntry.SYNTAX && ! syntaxTypes[mibEntry.ObjectName] ) {
                        if ( typeof mibEntry.SYNTAX == "object" ) {
                            syntaxTypes[mibEntry.ObjectName] = mibEntry.SYNTAX;
                        } else {
                            syntaxTypes[mibEntry.ObjectName] = syntaxTypes[mibEntry.SYNTAX];
                        }
                    }
                }
            }
        }
        return syntaxTypes;
    }

    loadFromFile (fileName) {
        const modulesBeforeLoad = this.getModuleNames();
        this.parser.Import (fileName);
        this.parser.Serialize ();
        const modulesAfterLoad = this.getModuleNames();
        const newModulesForTranslation = modulesAfterLoad.filter (moduleName => modulesBeforeLoad.indexOf (moduleName) === -1);
        newModulesForTranslation.forEach ( moduleName => this.addTranslationsForModule (moduleName) );
    }

    addTranslationsForModule (moduleName) {
	    const mibModule = this.parser.Modules[moduleName];

        if ( ! mibModule ) {
            throw new ReferenceError ("MIB module " + moduleName + " not loaded");
        }
        const entryArray = Object.values (mibModule);
        for ( let i = 0; i < entryArray.length ; i++ ) {
            const mibEntry = entryArray[i];
            const oid = mibEntry.OID;
            const namedPath = mibEntry.NameSpace;
            let moduleQualifiedName;
            if ( mibEntry.ObjectName ) {
                moduleQualifiedName = moduleName + "::" + mibEntry.ObjectName;
            } else {
                moduleQualifiedName = undefined;
            }
            if ( oid && namedPath ) {
                this.translations.oidToPath[oid] = namedPath;
                this.translations.pathToOid[namedPath] = oid;
            }
            if ( oid && moduleQualifiedName ) {
                this.translations.oidToModule[oid] = moduleQualifiedName;
                this.translations.moduleToOid[moduleQualifiedName] = oid;
            }
            if ( namedPath && moduleQualifiedName ) {
                this.translations.pathToModule[namedPath] = moduleQualifiedName;
                this.translations.moduleToPath[moduleQualifiedName] = namedPath;
            }
        }
    }

    getModule (moduleName) {
	    return this.parser.Modules[moduleName];
    }

    getModules (includeBase) {
        const modules = {};
        for ( let moduleName of Object.keys(this.parser.Modules) ) {
            if ( includeBase || ModuleStore.BASE_MODULES.indexOf (moduleName) == -1 ) {
                modules[moduleName] = this.parser.Modules[moduleName];
            }
        }
        return modules;
    }

    getModuleNames (includeBase) {
        const modules = [];
        for ( var moduleName of Object.keys(this.parser.Modules) ) {
            if ( includeBase || ModuleStore.BASE_MODULES.indexOf (moduleName) == -1 ) {
                modules.push (moduleName);
            }
        }
        return modules;
    }

    getProvidersForModule (moduleName) {
        const mibModule = this.parser.Modules[moduleName];
        const scalars = [];
        const tables = [];
        let mibEntry;
        let syntaxTypes;
        let entryArray;
        let currentTableProvider;
        let parentOid;
        let constraintsResults;
        let constraints;

        if ( ! mibModule ) {
            throw new ReferenceError ("MIB module " + moduleName + " not loaded");
        }
        syntaxTypes = this.getSyntaxTypes ();
        entryArray = Object.values (mibModule);
        for ( var i = 0; i < entryArray.length ; i++ ) {
            mibEntry = entryArray[i];
            var syntax = mibEntry.SYNTAX;
            var access = mibEntry["ACCESS"];
            var maxAccess = (typeof mibEntry["MAX-ACCESS"] != "undefined" ? mibEntry["MAX-ACCESS"] : (access ? AccessToMaxAccess[access] : "not-accessible"));
            var defVal = mibEntry["DEFVAL"];

            if ( syntax ) {
                constraintsResults = ModuleStore.getConstraintsFromSyntax (syntax, syntaxTypes);
                syntax = constraintsResults.syntax;
                constraints = constraintsResults.constraints;

                if ( syntax.startsWith ("SEQUENCE OF") ) {
                    // start of table
                    currentTableProvider = {
                        tableName: mibEntry.ObjectName,
                        type: MibProviderType.Table,
                        //oid: mibEntry.OID,
                        tableColumns: [],
                        tableIndex: [1]	 // default - assume first column is index
                    };
                    currentTableProvider.maxAccess = MaxAccess[maxAccess];

                    // read table to completion
                    while ( currentTableProvider || i >= entryArray.length ) {
                        i++;
                        mibEntry = entryArray[i];
                        if ( ! mibEntry ) {
                            tables.push (currentTableProvider);
                            currentTableProvider = null;
                            i--;
                            break;
                        }
                        syntax = mibEntry.SYNTAX;
                        access = mibEntry["ACCESS"];
                        maxAccess = (typeof mibEntry["MAX-ACCESS"] != "undefined" ? mibEntry["MAX-ACCESS"] : (access ? AccessToMaxAccess[access] : "not-accessible"));
                        defVal = mibEntry["DEFVAL"];

                        constraintsResults = ModuleStore.getConstraintsFromSyntax (syntax, syntaxTypes);
                        syntax = constraintsResults.syntax;
                        constraints = constraintsResults.constraints;

                        if ( mibEntry.MACRO == "SEQUENCE" ) {
                            // table entry sequence - ignore
                        } else if ( ! mibEntry["OBJECT IDENTIFIER"] ) {
                            // unexpected
                        } else {
                            parentOid = mibEntry["OBJECT IDENTIFIER"].split (" ")[0];
                            if ( parentOid == currentTableProvider.tableName ) {
                                // table entry
                                currentTableProvider.name = mibEntry.ObjectName;
                                currentTableProvider.oid = mibEntry.OID;
                                if ( mibEntry.INDEX ) {
                                    currentTableProvider.tableIndex = [];
                                    for ( var indexEntry of mibEntry.INDEX ) {
                                        indexEntry = indexEntry.trim ();
                                        if ( indexEntry.includes(" ") ) {
                                            if ( indexEntry.split(" ")[0] == "IMPLIED" ) {
                                                currentTableProvider.tableIndex.push ({
                                                    columnName: indexEntry.split(" ")[1],
                                                    implied: true
                                                });
                                            } else {
                                                // unknown condition - guess that last token is name
                                                currentTableProvider.tableIndex.push ({
                                                    columnName: indexEntry.split(" ").slice(-1)[0],
                                                });
                                            }
                                        } else {
                                            currentTableProvider.tableIndex.push ({
                                                columnName: indexEntry
                                            });
                                        }
                                    }
                                }
                                if ( mibEntry.AUGMENTS ) {
                                    currentTableProvider.tableAugments = mibEntry.AUGMENTS[0].trim();
                                    currentTableProvider.tableIndex = null;
                                }
                            } else if ( parentOid == currentTableProvider.name ) {
                                // table column
                                let columnType = syntaxTypes[syntax];
                                if (typeof columnType === 'object') {
                                    columnType = syntaxTypes[Object.keys(columnType)[0]];
                                }
                                var columnDefinition = {
                                    number: parseInt (mibEntry["OBJECT IDENTIFIER"].split (" ")[1]),
                                    name: mibEntry.ObjectName,
                                    type: columnType,
                                    maxAccess: MaxAccess[maxAccess]
                                };
                                if ( constraints ) {
                                    columnDefinition.constraints = constraints;
                                }
                                if (defVal) {
                                    columnDefinition.defVal = defVal;
                                }
                                // If this column has syntax RowStatus and
                                // the MIB module imports RowStatus from
                                // SNMPv2-TC, mark this column as the
                                // rowStatus column so we can act on it.
                                // (See lib/mibs/SNMPv2-TC.mib#L186.)
                                if ( syntax == "RowStatus" &&
                                        "IMPORTS" in mibModule &&
                                        Array.isArray(mibModule.IMPORTS["SNMPv2-TC"]) &&
                                        mibModule.IMPORTS["SNMPv2-TC"].includes("RowStatus") ) {

                                    // Mark this column as being rowStatus
                                    columnDefinition.rowStatus = true;
                                }
                                currentTableProvider.tableColumns.push (columnDefinition);
                            } else {
                                // table finished
                                tables.push (currentTableProvider);
                                // console.log ("Table: " + currentTableProvider.name);
                                currentTableProvider = null;
                                i--;
                            }
                        }
                    }
                } else if ( mibEntry.MACRO == "OBJECT-TYPE" ) {
                    // OBJECT-TYPE entries not in a table are scalars
                    let scalarType = syntaxTypes[syntax];
                    if (typeof scalarType === 'object') {
                        scalarType = syntaxTypes[Object.keys(scalarType)[0]];
                    }
                    var scalarDefinition = {
                        name: mibEntry.ObjectName,
                        type: MibProviderType.Scalar,
                        oid: mibEntry.OID,
                        scalarType: scalarType,
                        maxAccess: MaxAccess[maxAccess]
                    };

                    if (defVal) {
                        scalarDefinition.defVal = defVal;
                    }

                    if ( constraints ) {
                        scalarDefinition.constraints = constraints;
                    }
                    scalars.push (scalarDefinition);
                    // console.log ("Scalar: " + mibEntry.ObjectName);
                }
            }
        }
        return scalars.concat (tables);
    }

    loadBaseModules () {
        for ( const mibModule of ModuleStore.BASE_MODULES ) {
            this.parser.Import (__dirname + "/lib/mibs/" + mibModule + ".mib");
        }
        this.parser.Serialize ();
        this.getModuleNames (true).forEach( moduleName => this.addTranslationsForModule (moduleName) );
    }

    getConstraintsFromSyntax (syntax, syntaxTypes) {
        let constraints;
        if ( typeof syntaxTypes[syntax] === 'object' ) {
            syntax = syntaxTypes[syntax];
        }
        // detect INTEGER ranges, OCTET STRING sizes, and INTEGER enumerations
        if ( typeof syntax == "object" ) {
            let firstSyntaxKey = syntax[Object.keys(syntax)[0]];
            if ( firstSyntaxKey.ranges ) {
                constraints = {
                    ranges: firstSyntaxKey.ranges
                };
                syntax = Object.keys(syntax)[0];
            } else if ( firstSyntaxKey.sizes ) {
                constraints = {
                    sizes: firstSyntaxKey.sizes
                };
                syntax = Object.keys(syntax)[0];
            } else {
                constraints = {
                    enumeration: syntax.INTEGER
                };
                syntax = "INTEGER";
            }
        } else {
            constraints = null;
        }
        return {
            constraints: constraints,
            syntax: syntax
        };
    }

    translate (name, destinationFormat) {
        let sourceFormat;
        if ( name.includes ("::") ) {
            sourceFormat = OidFormat.module;
        } else if ( name.startsWith ("1.") ) {
            sourceFormat = OidFormat.oid;
        } else {
            sourceFormat = OidFormat.path;
        }
        const lowercaseDestinationFormat = destinationFormat.toLowerCase();
        if ( sourceFormat === lowercaseDestinationFormat ) {
            let testMap;
            switch ( sourceFormat ) {
                case OidFormat.oid: {
                    testMap = "oidToPath";
                    break;
                }
                case OidFormat.path: {
                    testMap = "pathToOid";
                    break;
                }
                case OidFormat.module: {
                    testMap = "moduleToOid";
                    break;
                }
            }
            const entryExists = this.translations[testMap][name];
            if ( entryExists === undefined ) {
                throw new Error ("No translation found for " + name);
            } else {
                return name;
            }
        } else {
            const capitalizedDestinationFormat = destinationFormat.charAt(0).toUpperCase() + destinationFormat.slice(1).toLowerCase();
            const translationMap = sourceFormat + "To" + capitalizedDestinationFormat;
            const translation = this.translations[translationMap][name];
            if ( ! translation ) {
                throw new Error ("No '" + destinationFormat + "' translation found for " + name);
            } else {
                return translation;
            }
        }
    }

    static create () {
	    const store = new ModuleStore ();
	    store.loadBaseModules ();
	    return store;
    }

    static readonly BASE_MODULES = [
        "RFC1155-SMI",
        "RFC1158-MIB",
        "RFC-1212",
        "RFC1213-MIB",
        "SNMPv2-SMI",
        "SNMPv2-CONF",
        "SNMPv2-TC",
        "SNMPv2-MIB"
    ];
}

class MibNode
{
    constructor (address, parent) {
        this.address = address;
        this.oid = this.address.join('.');
        this.parent = parent;
        this.children = {};
    }

    child (index) {
	    return this.children[index];
    }

    listChildren (lowest) {
	    const sorted = [];

        lowest = lowest || 0;

        this.children.forEach (function (c, i) {
            if (i >= lowest)
                sorted.push (i);
        });

        sorted.sort (function (a, b) {
            return (a - b);
        });

        return sorted;
    }

    findChildImmediatelyBefore (index) {
        const sortedChildrenKeys = Object.keys(this.children).sort(function (a, b) {
            return (a - b);
        });

        if ( sortedChildrenKeys.length === 0 ) {
            return null;
        }

        for ( var i = 0; i < sortedChildrenKeys.length; i++ ) {
            if ( index < sortedChildrenKeys[i] ) {
                if ( i === 0 ) {
                    return null;
                } else {
                    return this.children[sortedChildrenKeys[i - 1]];
                }
            }
        }
        return this.children[sortedChildrenKeys[sortedChildrenKeys.length - 1]];
    }

    isDescendant (address) {
	    return MibNode.oidIsDescended(this.address, address);
    }

    isAncestor (address) {
	    return MibNode.oidIsDescended (address, this.address);
    }

    getAncestorProvider () {
	    if ( this.provider ) {
		    return this;
	    } else if ( ! this.parent ) {
            return null;
        } else {
            return this.parent.getAncestorProvider ();
        }
    }

    getTableColumnFromInstanceNode () {
        if ( this.parent && this.parent.provider ) {
            return this.address[this.address.length - 1];
        } else if ( ! this.parent ) {
            return null;
        } else {
            return this.parent.getTableColumnFromInstanceNode ();
        }
    }

    getConstraintsFromProvider () {
        const providerNode = this.getAncestorProvider ();
        if ( ! providerNode ) {
            return null;
        }
        const provider = providerNode.provider;
        if ( provider.type == MibProviderType.Scalar ) {
            return provider.constraints;
        } else if ( provider.type == MibProviderType.Table ) {
            const columnNumber = this.getTableColumnFromInstanceNode ();
            if ( ! columnNumber ) {
                return null;
            }
            const columnDefinition = provider.tableColumns.filter (column => column.number == columnNumber)[0];
            return columnDefinition ? columnDefinition.constraints : null;
        } else {
            return null;
        }
    }

    setValue (newValue) {
        var len;
        var min;
        var max;
        var range;
        var found = false;
        var constraints = this.getConstraintsFromProvider ();
        if ( ! constraints ) {
            this.value = newValue;
            return true;
        }
        if ( constraints.enumeration ) {
            if ( ! constraints.enumeration[newValue] ) {
                return false;
            }
        } else if ( constraints.ranges ) {
            for ( range of constraints.ranges ) {
                min = "min" in range ? range.min : Number.MIN_SAFE_INTEGER;
                max = "max" in range ? range.max : Number.MAX_SAFE_INTEGER;
                if ( newValue >= min && newValue <= max ) {
                    found = true;
                    break;
                }
            }
            if ( ! found ) {
                return false;
            }
        } else if ( constraints.sizes ) {
            // if size is constrained, value must have a length property
            if ( newValue.length === undefined ) {
                return false;
            }
            len = newValue.length;
            for ( range of constraints.sizes ) {
                min = "min" in range ? range.min : Number.MIN_SAFE_INTEGER;
                max = "max" in range ? range.max : Number.MAX_SAFE_INTEGER;
                if ( len >= min && len <= max ) {
                    found = true;
                    break;
                }
            }
            if ( ! found ) {
                return false;
            }
        }
        this.value = newValue;
        return true;
    }

    getInstanceNodeForTableRow () {
        var childCount = Object.keys (this.children).length;
        if ( childCount == 0 ) {
            if ( this.value != null ) {
                return this;
            } else {
                return null;
            }
        } else if ( childCount == 1 ) {
            return this.children[0].getInstanceNodeForTableRow();
        } else if ( childCount > 1 ) {
            return null;
        }
    }

    getInstanceNodeForTableRowIndex (index) {
        var childCount = Object.keys (this.children).length;
        var remainingIndex;

        if ( childCount == 0 ) {
            if ( this.value != null ) {
                return this;
            } else {
                // not found
                return null;
            }
        } else {
            if ( index.length == 0 ) {
                return this.getInstanceNodeForTableRow();
            } else {
                var nextChildIndexPart = index[0];
                if ( nextChildIndexPart == null ) {
                    return null;
                }
                remainingIndex = index.slice(1);
                if ( this.children[nextChildIndexPart] ) {
                    return this.children[nextChildIndexPart].getInstanceNodeForTableRowIndex(remainingIndex);
                } else {
                    return null;
                }
            }
        }
    }

    getInstanceNodesForColumn () {
        var columnNode = this;
        var instanceNode = this;
        var instanceNodes = [];

        while (instanceNode && ( instanceNode == columnNode || columnNode.isAncestor (instanceNode.address) ) ) {
            instanceNode = instanceNode.getNextInstanceNode ();
            if ( instanceNode && columnNode.isAncestor (instanceNode.address) ) {
                instanceNodes.push (instanceNode);
            }
        }
        return instanceNodes;
    }

    getNextInstanceNode () {
        var siblingIndex;
        var childrenAddresses;

        var node = this;
        if ( this.value != null ) {
            // Need upwards traversal first
            node = this;
            while ( node ) {
                siblingIndex = node.address.slice(-1)[0];
                node = node.parent;
                if ( ! node ) {
                    // end of MIB
                    return null;
                } else {
                    childrenAddresses = Object.keys (node.children).sort ( (a, b) => a - b);
                    var siblingPosition = childrenAddresses.indexOf(siblingIndex.toString());
                    if ( siblingPosition + 1 < childrenAddresses.length ) {
                        node = node.children[childrenAddresses[siblingPosition + 1]];
                        break;
                    }
                }
            }
        }
        // Descent
        while ( node ) {
            if ( node.value != null ) {
                return node;
            }
            childrenAddresses = Object.keys (node.children).sort ( (a, b) => a - b);
            node = node.children[childrenAddresses[0]];
            if ( ! node ) {
                // unexpected
                return null;
            }
        }
    }

    delete () {
        if ( Object.keys (this.children) > 0 ) {
            throw new Error ("Cannot delete non-leaf MIB node");
        }
        var addressLastPart = this.address.slice(-1)[0];
        delete this.parent.children[addressLastPart];
        this.parent = null;
    }

    pruneUpwards () {
        if ( ! this.parent ) {
            return;
        }
        if ( Object.keys (this.children).length == 0 ) {
            var lastAddressPart = this.address.splice(-1)[0].toString();
            delete this.parent.children[lastAddressPart];
            this.parent.pruneUpwards();
            this.parent = null;
        }
    }

    dump (options) {
        var valueString;
        if ( ( ! options.leavesOnly || options.showProviders ) && this.provider ) {
            console.log (this.oid + " [" + MibProviderType[this.provider.type] + ": " + this.provider.name + "]");
        } else if ( ( ! options.leavesOnly ) || Object.keys (this.children).length == 0 ) {
            if ( this.value != null ) {
                valueString = " = ";
                valueString += options.showTypes ? ObjectType[this.valueType] + ": " : "";
                valueString += options.showValues ? this.value : "";
            } else {
                valueString = "";
            }
            console.log (this.oid + valueString);
        }
        for ( var node of Object.keys (this.children).sort ((a, b) => a - b)) {
            this.children[node].dump (options);
        }
    }

    oidIsDescended (oid, ancestor) {
        var ancestorAddress = Mib.convertOidToAddress(ancestor);
        var address = Mib.convertOidToAddress(oid);
        var isAncestor = true;

        if (address.length <= ancestorAddress.length) {
            return false;
        }

        ancestorAddress.forEach (function (o, i) {
            if (address[i] !== ancestorAddress[i]) {
                isAncestor = false;
            }
        });

        return isAncestor;
    }
}

export class Mib
{
    constructor () {
        var providersByOid;
        this.root = new MibNode ([], null);
        this.providerNodes = {};

        // this.providers will be modified throughout this code.
        // Keep this.providersByOid in sync with it
        providersByOid = this.providersByOid = {};
        this.providers = new Proxy({}, {
            set: function (target, key, value) {
                target[key] = value;
                providersByOid[value.oid] = value;
            },

            deleteProperty: function (target, key) {
                delete providersByOid[target[key].oid];
                delete target[key];
            }
        });
    }

    addNodesForOid (oidString) {
        var address = Mib.convertOidToAddress (oidString);
        return this.addNodesForAddress (address);
    }

    addNodesForAddress (address) {
        var node;
        var i;

        node = this.root;

        for (i = 0; i < address.length; i++) {
            if ( ! node.children.hasOwnProperty (address[i]) ) {
                node.children[address[i]] = new MibNode (address.slice(0, i + 1), node);
            }
            node = node.children[address[i]];
        }

        return node;
    }

    lookup (oid) {
        var address;

        address = Mib.convertOidToAddress (oid);
        return this.lookupAddress(address);
    }

    lookupAddress (address) {
        var i;
        var node;

        node = this.root;
        for (i = 0; i < address.length; i++) {
            if ( ! node.children.hasOwnProperty (address[i])) {
                return null;
            }
            node = node.children[address[i]];
        }

        return node;
    }

    getTreeNode (oid) {
        var address = Mib.convertOidToAddress (oid);
        var node;

        node = this.lookupAddress (address);
        // OID already on tree
        if ( node ) {
            return node;
        }

        while ( address.length > 0 ) {
            var last = address.pop ();
            var parent = this.lookupAddress (address);
            if ( parent ) {
                node = parent.findChildImmediatelyBefore (last);
                if ( !node )
                    return parent;
                while ( true ) {
                    // Find the last descendant
                    var childrenAddresses = Object.keys (node.children).sort ( (a, b) => a - b);
                    if ( childrenAddresses.length == 0 )
                        return node;
                    node = node.children[childrenAddresses[childrenAddresses.length - 1]];
                }
            }
        }
        return this.root;
    }

    getProviderNodeForInstance (instanceNode) {
        if ( instanceNode.provider ) {
            // throw new ReferenceError ("Instance node has provider which should never happen");
            return null;
        }
        return instanceNode.getAncestorProvider ();
    }

    addProviderToNode (provider) {
	    const node = this.addNodesForOid (provider.oid);

        node.provider = provider;
        if ( provider.type == MibProviderType.Table ) {
            if ( ! provider.tableIndex ) {
                provider.tableIndex = [1];
            }
        }
        this.providerNodes[provider.name] = node;
        return node;
    }

    getColumnFromProvider (provider, indexEntry) {
        var column = null;
        if ( indexEntry.columnName ) {
            column = provider.tableColumns.filter (column => column.name == indexEntry.columnName )[0];
        } else if ( indexEntry.columnNumber !== undefined && indexEntry.columnNumber !== null  ) {
            column = provider.tableColumns.filter (column => column.number == indexEntry.columnNumber )[0];
        }
        return column;
    }

    populateIndexEntryFromColumn (localProvider, indexEntry, i) {
        var column = null;
        var tableProviders;
        if ( ! indexEntry.columnName && ! indexEntry.columnNumber ) {
            throw new Error ("Index entry " + i + ": does not have either a columnName or columnNumber");
        }
        if ( indexEntry.foreign ) {
            // Explicit foreign table is first to search
            column = this.getColumnFromProvider (this.providers[indexEntry.foreign], indexEntry);
        } else {
            // If foreign table isn't given, search the local table next
            column = this.getColumnFromProvider (localProvider, indexEntry);
            if ( ! column ) {
                // as a last resort, try to find the column in a foreign table
                tableProviders = Object.values(this.providers).
                        filter ( prov => prov.type == MibProviderType.Table );
                for ( var provider of tableProviders ) {
                    column = this.getColumnFromProvider (provider, indexEntry);
                    if ( column ) {
                        indexEntry.foreign = provider.name;
                        break;
                    }
                }
            }
        }
        if ( ! column ) {
            throw new Error ("Could not find column for index entry with column " + indexEntry.columnName);
        }
        if ( indexEntry.columnName && indexEntry.columnName != column.name ) {
            throw new Error ("Index entry " + i + ": Calculated column name " + column.name +
                    "does not match supplied column name " + indexEntry.columnName);
        }
        if ( indexEntry.columnNumber && indexEntry.columnNumber != column.number ) {
            throw new Error ("Index entry " + i + ": Calculated column number " + column.number +
                    " does not match supplied column number " + indexEntry.columnNumber);
        }
        if ( ! indexEntry.columnName ) {
            indexEntry.columnName = column.name;
        }
        if ( ! indexEntry.columnNumber ) {
            indexEntry.columnNumber = column.number;
        }
        indexEntry.type = column.type;
    }

    registerProvider (provider) {
        this.providers[provider.name] = provider;
        if ( provider.type == MibProviderType.Table ) {
            if ( provider.tableAugments ) {
                if ( provider.tableAugments == provider.name ) {
                    throw new Error ("Table " + provider.name + " cannot augment itself");
                }
                var augmentProvider = this.providers[provider.tableAugments];
                if ( ! augmentProvider ) {
                    throw new Error ("Cannot find base table " + provider.tableAugments + " to augment");
                }
                provider.tableIndex = JSON.parse(JSON.stringify(augmentProvider.tableIndex));
                provider.tableIndex.map (index => index.foreign = augmentProvider.name);
            } else {
                if ( ! provider.tableIndex ) {
                    provider.tableIndex = [1]; // default to first column index
                }
                for ( var i = 0 ; i < provider.tableIndex.length ; i++ ) {
                    var indexEntry = provider.tableIndex[i];
                    if ( typeof indexEntry == 'number' ) {
                        provider.tableIndex[i] = {
                            columnNumber: indexEntry
                        };
                    } else if ( typeof indexEntry == 'string' ) {
                        provider.tableIndex[i] = {
                            columnName: indexEntry
                        };
                    }
                    indexEntry = provider.tableIndex[i];
                    this.populateIndexEntryFromColumn (provider, indexEntry, i);
                }
            }
        }
    }

    setScalarDefaultValue (name, value) {
        let provider = this.getProvider(name);
        provider.defVal = value;
    }

    setTableRowDefaultValues (name, values) {
        let provider = this.getProvider(name);
        let tc = provider.tableColumns;

        // We must be given an array of exactly the right number of columns
        if (values.length != tc.length) {
            throw new Error(`Incorrect values length: got ${values.length}; expected ${tc.length}`);
        }

        // Add defVal to each table column.
        tc.forEach((entry, i) => {
            if (typeof values[i] != "undefined") {
                entry.defVal = values[i];
            }
        });
    }

    setScalarRanges (name, ranges ) {
	    let provider = this.getProvider(name);
	    provider.constraints = { ranges };
    }

    setTableColumnRanges (name, column, ranges ) {
        let provider = this.getProvider(name);
        let tc = provider.tableColumns;
        tc[column].constraints = { ranges };
    }

    setScalarSizes (name, sizes ) {
        let provider = this.getProvider(name);
        provider.constraints = { sizes };
    }

    setTableColumnSizes (name, column, sizes ) {
        let provider = this.getProvider(name);
        let tc = provider.tableColumns;
        tc[column].constraints = { sizes };
    }

    registerProviders (providers) {
        for ( var provider of providers ) {
            this.registerProvider (provider);
        }
    }

    unregisterProvider (name) {
        var providerNode = this.providerNodes[name];
        if ( providerNode ) {
            var providerNodeParent = providerNode.parent;
            providerNode.delete();
            providerNodeParent.pruneUpwards();
            delete this.providerNodes[name];
        }
        delete this.providers[name];
    }

    getProvider (name) {
	    return this.providers[name];
    }

    getProviders () {
	    return this.providers;
    }

    dumpProviders () {
        var extraInfo;
        for ( var provider of Object.values(this.providers) ) {
            extraInfo = provider.type == MibProviderType.Scalar ? ObjectType[provider.scalarType] : "Columns = " + provider.tableColumns.length;
            console.log(MibProviderType[provider.type] + ": " + provider.name + " (" + provider.oid + "): " + extraInfo);
        }
    }

    getScalarValue (scalarName) {
        var providerNode = this.providerNodes[scalarName];
        if ( ! providerNode || ! providerNode.provider || providerNode.provider.type != MibProviderType.Scalar ) {
            throw new ReferenceError ("Failed to get node for registered MIB provider " + scalarName);
        }
        var instanceAddress = providerNode.address.concat ([0]);
        if ( ! this.lookup (instanceAddress) ) {
            throw new Error ("Failed created instance node for registered MIB provider " + scalarName);
        }
        var instanceNode = this.lookup (instanceAddress);
        return instanceNode.value;
    }

    setScalarValue (scalarName, newValue) {
        var providerNode;
        var instanceNode;
        var provider;

        if ( ! this.providers[scalarName] ) {
            throw new ReferenceError ("Provider " + scalarName + " not registered with this MIB");
        }

        providerNode = this.providerNodes[scalarName];
        if ( ! providerNode ) {
            providerNode = this.addProviderToNode (this.providers[scalarName]);
        }
        provider = providerNode.provider;
        if ( ! providerNode || ! provider || provider.type != MibProviderType.Scalar ) {
            throw new ReferenceError ("Could not find MIB node for registered provider " + scalarName);
        }
        var instanceAddress = providerNode.address.concat ([0]);
        instanceNode = this.lookup (instanceAddress);
        if ( ! instanceNode ) {
            this.addNodesForAddress (instanceAddress);
            instanceNode = this.lookup (instanceAddress);
            instanceNode.valueType = provider.scalarType;
        }
        instanceNode.value = newValue;
        // return instanceNode.setValue (newValue);
    }

    getProviderNodeForTable (table) {
        var providerNode;
        var provider;

        providerNode = this.providerNodes[table];
        if ( ! providerNode ) {
            throw new ReferenceError ("No MIB provider registered for " + table);
        }
        provider = providerNode.provider;
        if ( ! providerNode ) {
            throw new ReferenceError ("No MIB provider definition for registered provider " + table);
        }
        if ( provider.type != MibProviderType.Table ) {
            throw new TypeError ("Registered MIB provider " + table +
                " is not of the correct type (is type " + MibProviderType[provider.type] + ")");
        }
        return providerNode;
    }

    getOidAddressFromValue (value, indexPart) {
        var oidComponents;
        switch ( indexPart.type ) {
            case ObjectType.OID:
                oidComponents = value.split (".");
                break;
            case ObjectType.OctetString:
                if ( value instanceof Buffer ) {
                    // Buffer
                    oidComponents = Array.prototype.slice.call (value);
                } else {
                    // string
                    oidComponents = [...value].map (c => c.charCodeAt());
                }
                break;
            case ObjectType.IpAddress:
                return value.split (".");
            default:
                return [value];
        }
        if ( ! indexPart.implied && ! indexPart.length ) {
            oidComponents.unshift (oidComponents.length);
        }
        return oidComponents;
    }

    // What is this empty function here for?
    // getValueFromOidAddress (oid, indexPart) {
    // }

    getTableRowInstanceFromRow (provider, row) {
        var rowIndex = [];
        var foreignColumnParts;
        var localColumnParts;
        var localColumnPosition;
        var oidArrayForValue;

        // foreign columns are first in row
        foreignColumnParts = provider.tableIndex.filter ( indexPart => indexPart.foreign );
        for ( var i = 0; i < foreignColumnParts.length ; i++ ) {
            //rowIndex.push (row[i]);
            oidArrayForValue = this.getOidAddressFromValue (row[i], foreignColumnParts[i]);
            rowIndex = rowIndex.concat (oidArrayForValue);
        }
        // then local columns
        localColumnParts = provider.tableIndex.filter ( indexPart => ! indexPart.foreign );
        for ( var localColumnPart of localColumnParts ) {
            localColumnPosition = provider.tableColumns.findIndex (column => column.number == localColumnPart.columnNumber);
            oidArrayForValue = this.getOidAddressFromValue (row[foreignColumnParts.length + localColumnPosition], localColumnPart);
            rowIndex = rowIndex.concat (oidArrayForValue);
        }
        return rowIndex;
    }

    static getRowIndexFromOid (oid, index) {
        var addressRemaining = oid.split (".");
        var length = 0;
        var values = [];
        var value;
        for ( var indexPart of index ) {
            switch ( indexPart.type ) {
                case ObjectType.OID:
                    if ( indexPart.implied ) {
                        length = addressRemaining.length;
                    } else {
                        length = addressRemaining.shift ();
                    }
                    value = addressRemaining.splice (0, length);
                    values.push (value.join ("."));
                    break;
                case ObjectType.IpAddress:
                    length = 4;
                    value = addressRemaining.splice (0, length);
                    values.push (value.join ("."));
                    break;
                case ObjectType.OctetString:
                    if ( indexPart.implied ) {
                        length = addressRemaining.length;
                    } else {
                        length = addressRemaining.shift ();
                    }
                    value = addressRemaining.splice (0, length);
                    value = value.map (c => String.fromCharCode(c)).join ("");
                    values.push (value);
                    break;
                default:
                    values.push (parseInt (addressRemaining.shift ()) );
            }
        }
        return values;
    }

    getTableRowInstanceFromRowIndex (provider, rowIndex) {
        var rowIndexOid = [];
        var indexPart;
        var keyPart;
        for ( var i = 0; i < provider.tableIndex.length ; i++ ) {
            indexPart = provider.tableIndex[i];
            keyPart = rowIndex[i];
            rowIndexOid = rowIndexOid.concat (this.getOidAddressFromValue (keyPart, indexPart));
        }
        return rowIndexOid;
    }

    addTableRow (table, row) {
        var providerNode;
        var provider;
        var instance = [];
        var instanceAddress;
        var instanceNode;
        var rowValueOffset;

        if ( this.providers[table] && ! this.providerNodes[table] ) {
            this.addProviderToNode (this.providers[table]);
        }
        providerNode = this.getProviderNodeForTable (table);
        provider = providerNode.provider;
        rowValueOffset = provider.tableIndex.filter ( indexPart => indexPart.foreign ).length;
        instance = this.getTableRowInstanceFromRow (provider, row);
        for ( var i = 0; i < provider.tableColumns.length ; i++ ) {
            var column = provider.tableColumns[i];
            var isColumnIndex = provider.tableIndex.some ( indexPart => indexPart.columnNumber == column.number );
            // prevent not-accessible and accessible-for-notify index entries from being added as columns in the row
            if ( ! isColumnIndex || ! (column.maxAccess === MaxAccess['not-accessible'] || column.maxAccess === MaxAccess['accessible-for-notify']) ) {
                instanceAddress = providerNode.address.concat (column.number).concat (instance);
                this.addNodesForAddress (instanceAddress);
                instanceNode = this.lookup (instanceAddress);
                instanceNode.valueType = column.type;
                instanceNode.value = row[rowValueOffset + i];
            }
        }
    }

    getTableColumnDefinitions (table) {
        var providerNode;
        var provider;

        providerNode = this.getProviderNodeForTable (table);
        provider = providerNode.provider;
        return provider.tableColumns;
    }

    getTableColumnCells (table, columnNumber, includeInstances) {
        var provider = this.providers[table];
        var providerIndex = provider.tableIndex;
        var providerNode = this.getProviderNodeForTable (table);
        var columnNode = providerNode.children[columnNumber];
        if ( ! columnNode ) {
            return null;
        }
        var instanceNodes = columnNode.getInstanceNodesForColumn ();
        var instanceOid;
        var indexValues = [];
        var columnValues = [];

        for ( var instanceNode of instanceNodes ) {
            instanceOid = Mib.getSubOidFromBaseOid (instanceNode.oid, columnNode.oid);
            indexValues.push (Mib.getRowIndexFromOid (instanceOid, providerIndex));
            columnValues.push (instanceNode.value);
        }
        if ( includeInstances ) {
            return [ indexValues, columnValues ];
        } else {
            return columnValues;
        }
    }

    getTableRowCells (table, rowIndex) {
        var provider;
        var providerNode;
        var columnNode;
        var instanceAddress;
        var instanceNode;
        var row = [];
        var rowFound = false;

        provider = this.providers[table];
        providerNode = this.getProviderNodeForTable (table);
        instanceAddress = this.getTableRowInstanceFromRowIndex (provider, rowIndex);
        for ( var columnNumber of Object.keys (providerNode.children) ) {
            columnNode = providerNode.children[columnNumber];
            if ( columnNode ) {
                instanceNode = columnNode.getInstanceNodeForTableRowIndex (instanceAddress);
                if ( instanceNode ) {
                    row.push (instanceNode.value);
                    rowFound = true;
                } else {
                    row.push (null);
                }
            } else {
                row.push (null);
            }
        }
        if ( rowFound ) {
            return row;
        } else {
            return null;
        }
    }

    getTableCells (table, byRows, includeInstances) {
        var providerNode;
        var column;
        var data = [];

        providerNode = this.getProviderNodeForTable (table);
        for ( var columnNumber of Object.keys (providerNode.children) ) {
            column = this.getTableColumnCells (table, columnNumber, includeInstances);
            if ( includeInstances ) {
                data.push (...column);
                includeInstances = false;
            } else {
                data.push (column);
            }
        }

        if ( byRows ) {
            return Object.keys (data[0]).map (function (c) {
                return data.map (function (r) { return r[c]; });
            });
        } else {
            return data;
        }
    }

    getTableSingleCell (table, columnNumber, rowIndex) {
        var provider;
        var providerNode;
        var instanceAddress;
        var columnNode;
        var instanceNode;

        provider = this.providers[table];
        providerNode = this.getProviderNodeForTable (table);
        instanceAddress = this.getTableRowInstanceFromRowIndex (provider, rowIndex);
        columnNode = providerNode.children[columnNumber];
        instanceNode = columnNode.getInstanceNodeForTableRowIndex (instanceAddress);
        return instanceNode.value;
    }

    setTableSingleCell (table, columnNumber, rowIndex, value) {
        var provider;
        var providerNode;
        var columnNode;
        var instanceNode;
        var instanceAddress;

        provider = this.providers[table];
        providerNode = this.getProviderNodeForTable (table);
        instanceAddress = this.getTableRowInstanceFromRowIndex (provider, rowIndex);
        columnNode = providerNode.children[columnNumber];
        instanceNode = columnNode.getInstanceNodeForTableRowIndex (instanceAddress);
        instanceNode.value = value;
        // return instanceNode.setValue (value);
    }

    deleteTableRow (table, rowIndex) {
        var provider;
        var providerNode;
        var instanceAddress;
        var columnNode;
        var instanceNode;
        var instanceParentNode;

        provider = this.providers[table];
        providerNode = this.getProviderNodeForTable (table);
        instanceAddress = this.getTableRowInstanceFromRowIndex (provider, rowIndex);
        for ( var columnNumber of Object.keys (providerNode.children) ) {
            columnNode = providerNode.children[columnNumber];
            instanceNode = columnNode.getInstanceNodeForTableRowIndex (instanceAddress);
            if ( instanceNode ) {
                instanceParentNode = instanceNode.parent;
                instanceNode.delete();
                instanceParentNode.pruneUpwards();
            } else {
                throw new ReferenceError ("Cannot find row for index " + rowIndex + " at registered provider " + table);
            }
        }
        if ( Object.keys (this.providerNodes[table].children).length === 0 ) {
            delete this.providerNodes[table];
        }
        return true;
    }

    dump (options) {
        if ( ! options ) {
            options = {};
        }
        var completedOptions = {
            leavesOnly: options.leavesOnly === undefined ? true : options.leavesOnly,
            showProviders: options.showProviders === undefined ? true : options.showProviders,
            showValues: options.showValues === undefined ? true : options.showValues,
            showTypes: options.showTypes === undefined ? true : options.showTypes
        };
        this.root.dump (completedOptions);
    }

    static convertOidToAddress (oid) {
        var address;
        var oidArray;
        var i;

        if (typeof (oid) === 'object' && isArray(oid)) {
            address = oid;
        } else if (typeof (oid) === 'string') {
            address = oid.split('.');
        } else {
            throw new TypeError('oid (string or array) is required');
        }

        if (address.length < 1)
            throw new RangeError('object identifier is too short');

        oidArray = [];
        for (i = 0; i < address.length; i++) {
            var n;

            if (address[i] === '')
                continue;

            if (address[i] === true || address[i] === false) {
                throw new TypeError('object identifier component ' +
                    address[i] + ' is malformed');
            }

            n = Number(address[i]);

            if (isNaN(n)) {
                throw new TypeError('object identifier component ' +
                    address[i] + ' is malformed');
            }
            if (n % 1 !== 0) {
                throw new TypeError('object identifier component ' +
                    address[i] + ' is not an integer');
            }
            if (i === 0 && n > 2) {
                throw new RangeError('object identifier does not ' +
                    'begin with 0, 1, or 2');
            }
            if (i === 1 && n > 39) {
                throw new RangeError('object identifier second ' +
                    'component ' + n + ' exceeds encoding limit of 39');
            }
            if (n < 0) {
                throw new RangeError('object identifier component ' +
                    address[i] + ' is negative');
            }
            if (n > MAX_SIGNED_INT32) {
                throw new RangeError('object identifier component ' +
                    address[i] + ' is too large');
            }
            oidArray.push(n);
        }

        return oidArray;
    }

    static getSubOidFromBaseOid (oid, base) {
	    return oid.substring (base.length + 1);
    }

    static create = function () {
	    return new Mib ();
    }
}

class MibRequest
{
    constructor (requestDefinition) {
        this.operation = requestDefinition.operation;
        this.address = Mib.convertOidToAddress (requestDefinition.oid);
        this.oid = this.address.join ('.');
        this.providerNode = requestDefinition.providerNode;
        this.instanceNode = requestDefinition.instanceNode;
    }

    isScalar () {
        return this.providerNode && this.providerNode.provider &&
            this.providerNode.provider.type == MibProviderType.Scalar;
    }

    isTabular = function () {
        return this.providerNode && this.providerNode.provider &&
            this.providerNode.provider.type == MibProviderType.Table;
    }
}

export class Agent
{
    constructor (options, callback, mib) {
        DEBUG = options.debug;
        this.listener = new Listener (options, this);
        this.engine = new Engine (options.engineID);
        this.authorizer = new Authorizer (options);
        this.callback = callback || function () {};
        this.mib = mib || new Mib ();
        this.context = "";
        this.forwarder = new Forwarder (this.listener, this.callback);
    }

    getMib () {
	    return this.mib;
    }

    setMib (mib) {
	    this.mib = mib;
    }

    getAuthorizer () {
	    return this.authorizer;
    }

    registerProvider (provider) {
	    this.mib.registerProvider (provider);
    }

    registerProviders (providers) {
	    this.mib.registerProviders (providers);
    }

    unregisterProvider (name) {
	    this.mib.unregisterProvider (name);
    }

    getProvider (name) {
        return this.mib.getProvider (name);
    }

    getProviders () {
        return this.mib.getProviders ();
    }

    scalarReadCreateHandlerInternal (createRequest) {
        let provider = createRequest.provider;
        // If there's a default value specified...
        if ( provider && typeof provider.defVal != "undefined" ) {
            // ... then use it
            return provider.defVal;
        }

        // We don't have enough information to auto-create the scalar
        return undefined;
    }

    tableRowStatusHandlerInternal (createRequest) {
        let provider = createRequest.provider;
        let action = createRequest.action;
        let row = createRequest.row;
        let values = [];
        let missingDefVal = false;
        let rowIndexValues = Array.isArray( row ) ? row.slice(0) : [ row ];
        const tc = provider.tableColumns;

        tc.forEach(
            (columnInfo) => {
                let entries;

                // Index columns get successive values from the rowIndexValues array.
                // RowStatus columns get either "active" or "notInService" values.
                // Every other column requires a defVal.
                entries = provider.tableIndex.filter( entry => columnInfo.number === entry.columnNumber );
                if (entries.length > 0 ) {
                    // It's an index column. Use the next index value
                    values.push(rowIndexValues.shift());
                } else if ( columnInfo.rowStatus ) {
                    // It's the RowStatus column. Retain the action value for now; replaced later
                    values.push( RowStatus[action] );
                } else if ( "defVal" in columnInfo ) {
                    // Neither index nor RowStatus column, so use the default value
                    values.push( columnInfo.defVal );
                } else {
                    // Default value was required but not found
                    console.log("No defVal defined for column:", columnInfo);
                    missingDefVal = true;
                    values.push( undefined ); // just for debugging; never gets returned
                }
            }
        );

        // If a default value was missing, we can't auto-create the table row.
        // Otherwise, we're good to go: give 'em the column values.
        return missingDefVal ? undefined : values;
    }

    onMsg (buffer, rinfo) {

        let message;

        try {
            message = Listener.processIncoming (buffer, this.authorizer, this.callback);
        } catch (error) {
            this.callback (new ProcessingError ("Failure to process incoming message", error, rinfo, buffer));
            return;
        }

        if ( ! message ) {
            return;
        }

        // SNMPv3 discovery
        if ( message.version == Version3 && message.pdu.type == PduType.GetRequest &&
                ! message.hasAuthoritativeEngineID() && message.isReportable () ) {
            let reportMessage = message.createReportResponseMessage (this.engine, this.context);
            this.listener.send (reportMessage, rinfo);
            return;
        }

        // Request processing
        // debug (JSON.stringify (message.pdu, null, 2));
        if ( message.pdu.contextName && message.pdu.contextName != "" ) {
            this.onProxyRequest (message, rinfo);
        } else if ( message.pdu.type == PduType.GetRequest ) {
            this.getRequest (message, rinfo);
        } else if ( message.pdu.type == PduType.SetRequest ) {
            this.setRequest (message, rinfo);
        } else if ( message.pdu.type == PduType.GetNextRequest ) {
            this.getNextRequest (message, rinfo);
        } else if ( message.pdu.type == PduType.GetBulkRequest ) {
            this.getBulkRequest (message, rinfo);
        } else {
            this.callback (new RequestInvalidError ("Unexpected PDU type " +
                message.pdu.type + " (" + PduType[message.pdu.type] + ")"));
        }
    }

    castSetValue ( type, value ) {
        switch (type) {
            case ObjectType.Boolean:
                return !! value;

            case ObjectType.Integer:
                if ( typeof value != "number" && typeof value != "string" ) {
                    throw new Error("Invalid Integer", value);
                }
                return typeof value == "number" ? value : parseInt(value, 10);

            case ObjectType.OctetString:
                if ( value instanceof Buffer) {
                    return value.toString();
                } else if ( typeof value != "string" ) {
                    throw new Error("Invalid OctetString", value);
                } else {
                    return value;
                }

            case ObjectType.OID:
                if ( typeof value != "string" || ! value.match(/[0-9]+\([.][0-9]+\)+/) ) {
                    throw new Error("Invalid OID", value);
                }
                return value;

            case ObjectType.Counter:
            case ObjectType.Counter64:
                // Counters should be initialized to 0 (RFC2578, end of section 7.9)
                // We'll do so.
                return 0;

            case ObjectType.IpAddress:
                // A 32-bit internet address represented as OCTET STRING of length 4
                var bytes = value.split(".");
                if ( typeof value != "string" || bytes.length != 4 ) {
                    throw new Error("Invalid IpAddress", value);
                }
                return value;

            default :
                // Assume the caller knows what he's doing
                return value;
        }
    }


    tryCreateInstance (varbind, requestType) {
        var row;
        var column;
        var value;
        var subOid;
        var subAddr;
        var address;
        var fullAddress;
        var rowStatusColumn;
        var provider;
        var providersByOid = this.mib.providersByOid;
        var oid = varbind.oid;
        var createRequest;

        // Look for the provider.
        fullAddress = Mib.convertOidToAddress (oid);
        for ( address = fullAddress.slice(0) ; address.length > 0; address.pop() ) {
            subOid = address.join("."); // create an oid from the current address

            // Does this oid have a provider?
            provider = providersByOid[subOid];
            if (provider) {
                // Yup. Figure out what to do with it.
                // console.log(`FOUND MATCH TO ${oid}:\n`, providersByOid[subOid]);

                //
                // Scalar
                //
                if ( provider.type === MibProviderType.Scalar ) {

                    // Does this provider support "read-create"?
                    if ( provider.maxAccess != MaxAccess["read-create"] ) {
                        // Nope. Nothing we can do to help 'em.
                        return undefined;
                    }

                    // See if the provider says not to auto-create this scalar
                    if ( provider.createHandler === null ) {
                        return undefined;
                    }

                    // Call the provider-provided handler if available, or the default one if not
                    createRequest = {
                        provider: provider
                    };
                    value = ( provider.createHandler || this.scalarReadCreateHandlerInternal ) ( createRequest );
                    if ( typeof value == "undefined" ) {
                        // Handler said do not create instance
                        return undefined;
                    }

                    // Ensure the value is of the correct type, and save it
                    value = this.castSetValue ( provider.scalarType, value );
                    this.mib.setScalarValue ( provider.name, value );

                    // Now there should be an instanceNode available.
                    return {
                        instanceNode: this.mib.lookup (oid),
                        providerType: MibProviderType.Scalar
                    };
                }

                //
                // Table
                //

                // This is where we would support "read-create" of table
                // columns. RFC2578 section 7.1.12.1, however, implies
                // that rows should be created only via use of the
                // RowStatus column. We'll therefore avoid creating rows
                // based solely on any other column's "read-create"
                // max-access value.

                //
                // RowStatus setter (actions)
                //
                subOid = Mib.getSubOidFromBaseOid (oid, provider.oid);
                subAddr = subOid.split(".");
                column = parseInt(subAddr.shift(), 10);
                row = Mib.getRowIndexFromOid(subAddr.join("."), provider.tableIndex);
                rowStatusColumn = provider.tableColumns.reduce( (acc, current) => current.rowStatus ? current.number : acc, null );

                if ( requestType === PduType.SetRequest &&
                        typeof rowStatusColumn == "number" &&
                        column === rowStatusColumn ) {

                    if ( (varbind.value === RowStatus["createAndGo"] || varbind.value === RowStatus["createAndWait"]) &&
                            provider.createHandler !== null ) {

                        // The create handler will return an array
                        // containing all table column values for the
                        // table row to be added.
                        createRequest = {
                            provider: provider,
                            action: RowStatus[varbind.value],
                            row: row
                        };
                        value = ( provider.createHandler || this.tableRowStatusHandlerInternal )( createRequest );
                        if ( typeof value == "undefined") {
                            // Handler said do not create instance
                            return undefined;
                        }

                        if (! Array.isArray( value ) ) {
                            throw new Error("createHandler must return an array or undefined; got", value);
                        }

                        if ( value.length != provider.tableColumns.length ) {
                            throw new Error("createHandler's returned array must contain a value for for each column" );
                        }

                        // Map each column's value to the appropriate type
                        value = value.map( (v, i) => this.castSetValue ( provider.tableColumns[i].type, v ) );

                        // Add the table row
                        this.mib.addTableRow ( provider.name, value );

                        // Now there should be an instanceNode available.
                        return {
                            instanceNode: this.mib.lookup (oid),
                            providerType: MibProviderType.Table,
                            action: RowStatus[varbind.value],
                            rowIndex: row,
                            row: value
                        };

                    }
                }

                return undefined;
            }
        }

    //	console.log(`NO MATCH TO ${oid}`);
        return undefined;
    }

    isAllowed (pduType, provider, instanceNode) {
        var column;
        var maxAccess;
        var columnEntry;

        if (provider.type === MibProviderType.Scalar) {
            // It's a scalar. We'll use the provider's maxAccess
            maxAccess = provider.maxAccess;
        } else {
            // It's a table column. Use that column's maxAccess.
            column = instanceNode.getTableColumnFromInstanceNode();

            // In the typical case, we could use (column - 1) to index
            // into tableColumns to get to the correct entry. There is no
            // guarantee, however, that column numbers in the OID are
            // necessarily consecutive; theoretically some could be
            // missing. We'll therefore play it safe and search for the
            // specified column entry.

            columnEntry = provider.tableColumns.find(entry => entry.number === column);
            maxAccess = columnEntry ? columnEntry.maxAccess || MaxAccess['not-accessible'] : MaxAccess['not-accessible'];
        }

        switch ( PduType[pduType] ) {
            case "SetRequest":
                // SetRequest requires at least read-write access
                return maxAccess >= MaxAccess["read-write"];

            case "GetRequest":
            case "GetNextRequest":
            case "GetBulkRequest":
                // GetRequests require at least read-only access
                return maxAccess >= MaxAccess["read-only"];

            default:
                // Disallow other pdu types
                return false;
        }
    }

    request (requestMessage, rinfo) {
        var me = this;
        var varbindsCompleted = 0;
        var requestPdu = requestMessage.pdu;
        var varbindsLength = requestPdu.varbinds.length;
        var responsePdu = requestPdu.getResponsePduForRequest ();
        var mibRequests = [];
        var handlers = [];
        var createResult = [];
        var oldValues = [];
        var securityName = requestMessage.version == Version3 ? requestMessage.user.name : requestMessage.community;

        for ( let i = 0; i < requestPdu.varbinds.length; i++ ) {
            let instanceNode = this.mib.lookup (requestPdu.varbinds[i].oid);
            let providerNode;
            let rowStatusColumn;
            let getIcsHandler;

            // If we didn't find an instance node, see if we can
            // automatically create it, either because it has
            // "read-create" MAX-ACCESS, or because it's a RowStatus SET
            // indicating create.
            if ( ! instanceNode ) {
                createResult[i] = this.tryCreateInstance(requestPdu.varbinds[i], requestPdu.type);
                if ( createResult[i] ) {
                    instanceNode = createResult[i].instanceNode;
                }
            }

            // workaround re-write of OIDs less than 4 digits due to asn1-ber length limitation
            if ( requestPdu.varbinds[i].oid.split('.').length < 4 ) {
                requestPdu.varbinds[i].oid = "1.3.6.1";
            }

            if ( ! instanceNode ) {
                mibRequests[i] = new MibRequest ({
                    operation: requestPdu.type,
                    oid: requestPdu.varbinds[i].oid
                });
                handlers[i] = function getNsoHandler (mibRequestForNso) {
                    mibRequestForNso.done ({
                        errorStatus: ErrorStatus.NoError,
                        type: ObjectType.NoSuchObject,
                        value: null
                    });
                };
            } else {
                providerNode = this.mib.getProviderNodeForInstance (instanceNode);
                if ( ! providerNode || instanceNode.value === undefined ) {
                    mibRequests[i] = new MibRequest ({
                        operation: requestPdu.type,
                        oid: requestPdu.varbinds[i].oid
                    });
                    handlers[i] = function getNsiHandler (mibRequestForNsi) {
                        mibRequestForNsi.done ({
                            errorStatus: ErrorStatus.NoError,
                            type: ObjectType.NoSuchInstance,
                            value: null
                        });
                    };
                } else if ( ! this.isAllowed(requestPdu.type, providerNode.provider, instanceNode ) ) {
                    // requested access not allowed (by MAX-ACCESS)
                    mibRequests[i] = new MibRequest ({
                        operation: requestPdu.type,
                        oid: requestPdu.varbinds[i].oid
                    });
                    handlers[i] = function getRanaHandler (mibRequestForRana) {
                        mibRequestForRana.done ({
                            errorStatus: ErrorStatus.NoAccess,
                            type: ObjectType.Null,
                            value: null
                        });
                    };
                } else if ( this.authorizer.getAccessControlModelType () == AccessControlModelType.Simple &&
                        ! this.authorizer.getAccessControlModel ().isAccessAllowed (requestMessage.version, securityName, requestMessage.pdu.type) ) {
                    // Access control check
                    mibRequests[i] = new MibRequest ({
                        operation: requestPdu.type,
                        oid: requestPdu.varbinds[i].oid
                    });
                    handlers[i] = function getAccessDeniedHandler (mibRequestForAccessDenied) {
                        mibRequestForAccessDenied.done ({
                            errorStatus: ErrorStatus.NoAccess,
                            type: ObjectType.Null,
                            value: null
                        });
                    };
                } else if ( requestPdu.type === PduType.SetRequest &&
                        providerNode.provider.type == MibProviderType.Table &&
                        typeof (rowStatusColumn = providerNode.provider.tableColumns.reduce(
                                    (acc, current) => current.rowStatus ? current.number : acc, null )) == "number" &&
                        instanceNode.getTableColumnFromInstanceNode() === rowStatusColumn) {

                    getIcsHandler = function (mibRequestForIcs) {
                        mibRequestForIcs.done ({
                            errorStatus: ErrorStatus.InconsistentValue,
                            type: ObjectType.Null,
                            value: null
                        });
                    };

                    requestPdu.varbinds[i].requestValue = this.castSetValue (requestPdu.varbinds[i].type, requestPdu.varbinds[i].value);
                    switch ( requestPdu.varbinds[i].value ) {
                        case RowStatus["active"]:
                        case RowStatus["notInService"]:
                            // Setting either of these states, when the
                            // row already exists, is fine
                            break;

                        case RowStatus["destroy"]:
                            // This case is handled later
                            break;

                        case RowStatus["createAndGo"]:
                            // Valid if this was a new row creation, but now set to active
                            if ( instanceNode.value === RowStatus["createAndGo"] ) {
                                requestPdu.varbinds[i].value = RowStatus["active"];
                            } else {
                                // Row already existed
                                mibRequests[i] = new MibRequest ({
                                    operation: requestPdu.type,
                                    oid: requestPdu.varbinds[i].oid
                                });
                                handlers[i] = getIcsHandler;
                            }
                            break;

                        case RowStatus["createAndWait"]:
                            // Valid if this was a new row creation, but now set to notInService
                            if ( instanceNode.value === RowStatus["createAndWait"] ) {
                                requestPdu.varbinds[i].value = RowStatus["notInService"];
                            } else {
                                // Row already existed
                                mibRequests[i] = new MibRequest ({
                                    operation: requestPdu.type,
                                    oid: requestPdu.varbinds[i].oid
                                });
                                handlers[i] = getIcsHandler;
                            }
                            break;

                        case RowStatus["notReady"]:
                        default:
                            // It's not ever legal to set the RowStatus to
                            // any value but the six that are defined, and
                            // it's not legal to change the state to
                            // "notReady".
                            //
                            // The row already exists, as determined by
                            // the fact that we have an instanceNode, so
                            // we can not apply a create action to the
                            // RowStatus column, as dictated RFC-2579.
                            // (See the summary state table on Page 8
                            // (inconsistent value)
                            mibRequests[i] = new MibRequest ({
                                operation: requestPdu.type,
                                oid: requestPdu.varbinds[i].oid
                            });
                            handlers[i] = getIcsHandler;
                            break;
                    }
                }

                if ( requestPdu.type === PduType.SetRequest && ! createResult[i] ) {
                    oldValues[i] = instanceNode.value;
                }

                if ( ! handlers[i] ) {
                    mibRequests[i] = new MibRequest ({
                        operation: requestPdu.type,
                        providerNode: providerNode,
                        instanceNode: instanceNode,
                        oid: requestPdu.varbinds[i].oid
                    });

                    if ( requestPdu.type == PduType.SetRequest ) {
                        mibRequests[i].setType = requestPdu.varbinds[i].type;
                        mibRequests[i].setValue = requestPdu.varbinds[i].requestValue || requestPdu.varbinds[i].value;
                    }
                    handlers[i] = providerNode.provider.handler;
                }
            }

            (function (savedIndex) {
                let responseVarbind;
                mibRequests[savedIndex].done = function (error) {
                    let rowIndex = null;
                    let row = null;
                    let deleted = false;
                    let column = -1;
                    responseVarbind = {
                        oid: mibRequests[savedIndex].oid
                    };
                    if ( error ) {
                        if ( (typeof responsePdu.errorStatus == "undefined" || responsePdu.errorStatus == ErrorStatus.NoError) && error.errorStatus != ErrorStatus.NoError ) {
                            responsePdu.errorStatus = error.errorStatus;
                            responsePdu.errorIndex = savedIndex + 1;
                        }
                        responseVarbind.type = error.type || ObjectType.Null;
                        responseVarbind.value = error.value || null;
                        //responseVarbind.errorStatus: error.errorStatus
                        if ( error.errorStatus != ErrorStatus.NoError ) {
                            responseVarbind.errorStatus = error.errorStatus;
                        }
                    } else {
                        let provider = providerNode ? providerNode.provider : null;
                        let providerName = provider ? provider.name : null;
                        let subOid;
                        let subAddr;
                        if ( providerNode && providerNode.provider && providerNode.provider.type == MibProviderType.Table ) {
                            column = instanceNode.getTableColumnFromInstanceNode();
                            subOid = Mib.getSubOidFromBaseOid (instanceNode.oid, provider.oid);
                            subAddr = subOid.split(".");
                            subAddr.shift(); // shift off the column number, leaving the row index values
                            rowIndex = Mib.getRowIndexFromOid( subAddr.join("."), provider.tableIndex );
                            row = me.mib.getTableRowCells ( providerName, rowIndex );
                        }
                        if ( requestPdu.type == PduType.SetRequest ) {
                            // Is this a RowStatus column with a value of 6 (delete)?
                            let rowStatusColumn = provider.type == MibProviderType.Table
                                ? provider.tableColumns.reduce( (acc, current) => current.rowStatus ? current.number : acc, null )
                                : null;
                            if ( requestPdu.varbinds[savedIndex].value === RowStatus["destroy"] &&
                                typeof rowStatusColumn == "number" &&
                                column === rowStatusColumn ) {

                                // Yup. Do the deletion.
                                me.mib.deleteTableRow ( providerName, rowIndex );
                                deleted = true;

                                // This is going to return the prior state of the RowStatus column,
                                // i.e., either "active" or "notInService". That feels wrong, but there
                                // is no value we can set it to to indicate just-deleted. One would
                                // think we could set it to "notReady", but that is explicitly defined
                                // in RFC-2579 as "the conceptual row exists in the agent", which is
                                // no longer the case now that we've deleted the row. We're not allowed
                                // to ever return "destroy" as a status, so that doesn't give us an
                                // option either.

                            } else {
                                // No special handling required. Just save the new value.
                                let setResult = mibRequests[savedIndex].instanceNode.setValue (me.castSetValue (
                                    requestPdu.varbinds[savedIndex].type,
                                    requestPdu.varbinds[savedIndex].value
                                ));
                                if ( ! setResult ) {
                                    if ( typeof responsePdu.errorStatus == "undefined" || responsePdu.errorStatus == ErrorStatus.NoError ) {
                                        responsePdu.errorStatus = ErrorStatus.WrongValue;
                                        responsePdu.errorIndex = savedIndex + 1;
                                    }
                                    responseVarbind.errorStatus = ErrorStatus.WrongValue;
                                }
                            }
                        }
                        if ( ( requestPdu.type == PduType.GetNextRequest || requestPdu.type == PduType.GetBulkRequest ) &&
                                requestPdu.varbinds[savedIndex].type == ObjectType.EndOfMibView ) {
                            responseVarbind.type = ObjectType.EndOfMibView;
                        } else {
                            responseVarbind.type = mibRequests[savedIndex].instanceNode.valueType;
                        }
                        responseVarbind.value = mibRequests[savedIndex].instanceNode.value;
                    }
                    if ( providerNode && providerNode.provider && providerNode.provider.name ) {
                        responseVarbind.providerName = providerNode.provider.name;
                    }
                    if ( requestPdu.type == PduType.GetNextRequest || requestPdu.type == PduType.GetNextRequest ) {
                        responseVarbind.previousOid = requestPdu.varbinds[savedIndex].previousOid;
                    }
                    if ( requestPdu.type == PduType.SetRequest ) {
                        if ( oldValues[savedIndex] !== undefined ) {
                            responseVarbind.oldValue = oldValues[savedIndex];
                        }
                        responseVarbind.requestType = requestPdu.varbinds[savedIndex].type;
                        if ( requestPdu.varbinds[savedIndex].requestValue ) {
                            responseVarbind.requestValue = me.castSetValue (requestPdu.varbinds[savedIndex].type, requestPdu.varbinds[savedIndex].requestValue);
                        } else {
                            responseVarbind.requestValue = me.castSetValue (requestPdu.varbinds[savedIndex].type, requestPdu.varbinds[savedIndex].value);
                        }
                    }
                    if ( createResult[savedIndex] ) {
                        responseVarbind.autoCreated = true;
                    } else if ( deleted ) {
                        responseVarbind.deleted = true;
                    }
                    if ( providerNode && providerNode.provider.type == MibProviderType.Table ) {
                        responseVarbind.column = column;
                        responseVarbind.columnPosition = providerNode.provider.tableColumns.findIndex(tc => tc.number == column);
                        responseVarbind.rowIndex = rowIndex;
                        if ( ! deleted && rowIndex ) {
                            row = me.mib.getTableRowCells ( providerNode.provider.name, rowIndex );
                        }
                        responseVarbind.row = row;
                    }
                    me.setSingleVarbind (responsePdu, savedIndex, responseVarbind);
                    if ( ++varbindsCompleted == varbindsLength) {
                        me.sendResponse.call (me, rinfo, requestMessage, responsePdu);
                    }
                };
            })(i);
            if ( handlers[i] ) {
                handlers[i] (mibRequests[i]);
            } else {
                mibRequests[i].done ();
            }
        }
    }

    getRequest (requestMessage, rinfo) {
        this.request (requestMessage, rinfo);
    }

    setRequest (requestMessage, rinfo) {
	    this.request (requestMessage, rinfo);
    }

    addGetNextVarbind (targetVarbinds, startOid) {
        var startNode;
        var getNextNode;

        try {
            startNode = this.mib.lookup (startOid);
        } catch ( error ) {
            startOid = '1.3.6.1';
            startNode = this.mib.lookup (startOid);
        }

        if ( ! startNode ) {
            // Off-tree start specified
            startNode = this.mib.getTreeNode (startOid);
        }
        getNextNode = startNode.getNextInstanceNode();
        if ( ! getNextNode ) {
            // End of MIB
            targetVarbinds.push ({
                previousOid: startOid,
                oid: startOid,
                type: ObjectType.EndOfMibView,
                value: null
            });
        } else {
            // Normal response
            targetVarbinds.push ({
                previousOid: startOid,
                oid: getNextNode.oid,
                type: getNextNode.valueType,
                value: getNextNode.value
            });
        }

        return getNextNode;
    }

    getNextRequest (requestMessage, rinfo) {
        var requestPdu = requestMessage.pdu;
        var varbindsLength = requestPdu.varbinds.length;
        var getNextVarbinds = [];

        for (var i = 0 ; i < varbindsLength ; i++ ) {
            this.addGetNextVarbind (getNextVarbinds, requestPdu.varbinds[i].oid);
        }

        requestMessage.pdu.varbinds = getNextVarbinds;
        this.request (requestMessage, rinfo);
    }

    getBulkRequest (requestMessage, rinfo) {
        var requestPdu = requestMessage.pdu;
        var requestVarbinds = requestPdu.varbinds;
        var getBulkVarbinds = [];
        var startOid = [];
        var getNextNode;
        var endOfMib = false;

        for (var n = 0 ; n < Math.min (requestPdu.nonRepeaters, requestVarbinds.length) ; n++ ) {
            this.addGetNextVarbind (getBulkVarbinds, requestVarbinds[n].oid);
        }

        if ( requestPdu.nonRepeaters < requestVarbinds.length ) {

            for (var v = requestPdu.nonRepeaters ; v < requestVarbinds.length ; v++ ) {
                startOid.push (requestVarbinds[v].oid);
            }

            while ( getBulkVarbinds.length < requestPdu.maxRepetitions && ! endOfMib ) {
                for (var w = requestPdu.nonRepeaters ; w < requestVarbinds.length ; w++ ) {
                    if (getBulkVarbinds.length < requestPdu.maxRepetitions ) {
                        getNextNode = this.addGetNextVarbind (getBulkVarbinds, startOid[w - requestPdu.nonRepeaters]);
                        if ( getNextNode ) {
                            startOid[w - requestPdu.nonRepeaters] = getNextNode.oid;
                            if ( getNextNode.type == ObjectType.EndOfMibView ) {
                                endOfMib = true;
                            }
                        }
                    }
                }
            }
        }

        requestMessage.pdu.varbinds = getBulkVarbinds;
        this.request (requestMessage, rinfo);
    }

    setSingleVarbind (responsePdu, index, responseVarbind) {
        responsePdu.varbinds[index] = responseVarbind;
    }

    sendResponse (rinfo, requestMessage, responsePdu) {
        var responseMessage = requestMessage.createResponseForRequest (responsePdu);
        this.listener.send (responseMessage, rinfo);
        this.callback (null, Listener.formatCallbackData (responseMessage.pdu, rinfo) );
    }

    onProxyRequest (message, rinfo) {
        var contextName = message.pdu.contextName;
        var proxy;
        var proxiedPduId;
        var proxiedUser;

        if ( message.version != Version3 ) {
            this.callback (new RequestFailedError ("Only SNMP version 3 contexts are supported"));
            return;
        }
        proxy = this.forwarder.getProxy (contextName);
        if ( ! proxy ) {
            this.callback (new RequestFailedError ("No proxy found for message received with context " + contextName));
            return;
        }
        if ( ! proxy.session.msgSecurityParameters ) {
            // Discovery required - but chaining not implemented from here yet
            proxy.session.sendV3Discovery (null, null, this.callback, {});
        } else {
            message.msgSecurityParameters = proxy.session.msgSecurityParameters;
            message.setAuthentication ( ! (proxy.user.level == SecurityLevel.noAuthNoPriv));
            message.setPrivacy (proxy.user.level == SecurityLevel.authPriv);
            proxiedUser = message.user;
            message.user = proxy.user;
            message.buffer = null;
            message.pdu.contextEngineID = proxy.session.msgSecurityParameters.msgAuthoritativeEngineID;
            message.pdu.contextName = "";
            proxiedPduId = message.pdu.id;
            message.pdu.id = _generateId ();
            var req = new Req (proxy.session, message, null, this.callback, {}, true);
            req.port = proxy.port;
            req.proxiedRinfo = rinfo;
            req.proxiedPduId = proxiedPduId;
            req.proxiedUser = proxiedUser;
            req.proxiedEngine = this.engine;
            proxy.session.send (req);
        }
    }

    getForwarder () {
        return this.forwarder;
    }

    close () {
	    this.listener.close ();
    };

    static create (options, callback, mib) {
        var agent = new Agent (options, callback, mib);
        agent.listener.startListening ();
        return agent;
    }
}

class Forwarder
{
    constructor (listener, callback) {
        this.proxies = {};
        this.listener = listener;
        this.callback = callback;
    }

    addProxy (proxy) {
        var options = {
            version: Version3,
            port: proxy.port,
            transport: proxy.transport
        };
        proxy.session = Session.createV3 (proxy.target, proxy.user, options);
        proxy.session.proxy = proxy;
        proxy.session.proxy.listener = this.listener;
        this.proxies[proxy.context] = proxy;
        proxy.session.sendV3Discovery (null, null, this.callback);
    }

    deleteProxy (proxyName) {
        var proxy = this.proxies[proxyName];

        if ( proxy && proxy.session ) {
            proxy.session.close ();
        }
        delete this.proxies[proxyName];
    }

    getProxy (proxyName) {
	    return this.proxies[proxyName];
    }

    getProxies () {
	    return this.proxies;
    }

    dumpProxies () {
        var dump = {};
        for ( var proxy of Object.values (this.proxies) ) {
            dump[proxy.context] = {
                context: proxy.context,
                target: proxy.target,
                user: proxy.user,
                port: proxy.port
            };
        }
        console.log (JSON.stringify (dump, null, 2));
    }
}

class AgentXPdu
{
    constructor () {
    }

    toBuffer (): Buffer {
        var buffer = new SmartBuffer();
        this.writeHeader (buffer);
        switch ( this.pduType ) {
            case AgentXPduType.Open:
                buffer.writeUInt32BE (this.timeout);
                AgentXPdu.writeOid (buffer, this.oid);
                AgentXPdu.writeOctetString (buffer, this.descr);
                break;
            case AgentXPduType.Close:
                buffer.writeUInt8 (5);  // reasonShutdown == 5
                buffer.writeUInt8 (0);  // 3 x reserved bytes
                buffer.writeUInt8 (0);
                buffer.writeUInt8 (0);
                break;
            case AgentXPduType.Register:
                buffer.writeUInt8 (this.timeout);
                buffer.writeUInt8 (this.priority);
                buffer.writeUInt8 (this.rangeSubid);
                buffer.writeUInt8 (0);
                AgentXPdu.writeOid (buffer, this.oid);
                break;
            case AgentXPduType.Unregister:
                buffer.writeUInt8 (0);  // reserved
                buffer.writeUInt8 (this.priority);
                buffer.writeUInt8 (this.rangeSubid);
                buffer.writeUInt8 (0);  // reserved
                AgentXPdu.writeOid (buffer, this.oid);
                break;
            case AgentXPduType.AddAgentCaps:
                AgentXPdu.writeOid (buffer, this.oid);
                AgentXPdu.writeOctetString (buffer, this.descr);
                break;
            case AgentXPduType.RemoveAgentCaps:
                AgentXPdu.writeOid (buffer, this.oid);
                break;
            case AgentXPduType.Notify:
                AgentXPdu.writeVarbinds (buffer, this.varbinds);
                break;
            case AgentXPduType.Ping:
                break;
            case AgentXPduType.Response:
                buffer.writeUInt32BE (this.sysUpTime);
                buffer.writeUInt16BE (this.error);
                buffer.writeUInt16BE (this.index);
                AgentXPdu.writeVarbinds (buffer, this.varbinds);
                break;
            default:
                // unknown PDU type - should never happen as we control these
        }
        buffer.writeUInt32BE (buffer.length - 20, 16);
        return buffer.toBuffer ();
    }

    writeHeader (buffer) {
        this.flags = this.flags | 0x10;  // set NETWORK_BYTE_ORDER

        buffer.writeUInt8 (1);  // h.version = 1
        buffer.writeUInt8 (this.pduType);
        buffer.writeUInt8 (this.flags);
        buffer.writeUInt8 (0);  // reserved byte
        buffer.writeUInt32BE (this.sessionID);
        buffer.writeUInt32BE (this.transactionID);
        buffer.writeUInt32BE (this.packetID);
        buffer.writeUInt32BE (0);
        return buffer;
    }

    readHeader (buffer) {
        this.version = buffer.readUInt8 ();
        this.pduType = buffer.readUInt8 ();
        this.flags = buffer.readUInt8 ();
        buffer.readUInt8 ();   // reserved byte
        this.sessionID = buffer.readUInt32BE ();
        this.transactionID = buffer.readUInt32BE ();
        this.packetID = buffer.readUInt32BE ();
        this.payloadLength = buffer.readUInt32BE ();
    }

    static createFromVariables (vars) {
        var pdu = new AgentXPdu ();
        pdu.flags = vars.flags ? vars.flags | 0x10 : 0x10;  // set NETWORK_BYTE_ORDER to big endian
        pdu.pduType = vars.pduType || AgentXPduType.Open;
        pdu.sessionID = vars.sessionID || 0;
        pdu.transactionID = vars.transactionID || 0;
        pdu.packetID = vars.packetID || ++AgentXPdu.packetID;
        switch ( pdu.pduType ) {
            case AgentXPduType.Open:
                pdu.timeout = vars.timeout || 0;
                pdu.oid = vars.oid || null;
                pdu.descr = vars.descr || null;
                break;
            case AgentXPduType.Close:
                break;
            case AgentXPduType.Register:
                pdu.timeout = vars.timeout || 0;
                pdu.oid = vars.oid || null;
                pdu.priority = vars.priority || 127;
                pdu.rangeSubid = vars.rangeSubid || 0;
                break;
            case AgentXPduType.Unregister:
                pdu.oid = vars.oid || null;
                pdu.priority = vars.priority || 127;
                pdu.rangeSubid = vars.rangeSubid || 0;
                break;
            case AgentXPduType.AddAgentCaps:
                pdu.oid = vars.oid;
                pdu.descr = vars.descr;
                break;
            case AgentXPduType.RemoveAgentCaps:
                pdu.oid = vars.oid;
                break;
            case AgentXPduType.Notify:
                pdu.varbinds = vars.varbinds;
                break;
            case AgentXPduType.Ping:
                break;
            case AgentXPduType.Response:
                pdu.sysUpTime = vars.sysUpTime || 0;
                pdu.error = vars.error || 0;
                pdu.index = vars.index || 0;
                pdu.varbinds = vars.varbinds || null;
                break;
            default:
                // unsupported PDU type - should never happen as we control these
                throw new RequestInvalidError ("Unknown PDU type '" + pdu.pduType
                        + "' in created PDU");

        }

        return pdu;
    }

    static createFromBuffer (socketBuffer) {
        var pdu = new AgentXPdu ();

        var buffer = SmartBuffer.fromBuffer (socketBuffer);
        pdu.readHeader (buffer);

        switch ( pdu.pduType ) {
            case AgentXPduType.Response:
                pdu.sysUpTime = buffer.readUInt32BE ();
                pdu.error = buffer.readUInt16BE ();
                pdu.index = buffer.readUInt16BE ();
                break;
            case AgentXPduType.Get:
            case AgentXPduType.GetNext:
                pdu.searchRangeList = AgentXPdu.readSearchRangeList (buffer, pdu.payloadLength);
                break;
            case AgentXPduType.GetBulk:
                pdu.nonRepeaters = buffer.readUInt16BE ();
                pdu.maxRepetitions = buffer.readUInt16BE ();
                pdu.searchRangeList = AgentXPdu.readSearchRangeList (buffer, pdu.payloadLength - 4);
                break;
            case AgentXPduType.TestSet:
                pdu.varbinds = AgentXPdu.readVarbinds (buffer, pdu.payloadLength);
                break;
            case AgentXPduType.CommitSet:
            case AgentXPduType.UndoSet:
            case AgentXPduType.CleanupSet:
                break;
            default:
                // Unknown PDU type - shouldn't happen as master agents shouldn't send administrative PDUs
                throw new RequestInvalidError ("Unknown PDU type '" + pdu.pduType
                        + "' in request");
        }
        return pdu;
    }

    static writeOid (buffer, oid, include = 0) {
        var prefix;
        if ( oid ) {
            var address = oid.split ('.').map ( Number );
            if ( address.length >= 5 && address.slice (0, 4).join('.') == '1.3.6.1' ) {
                prefix = address[4];
                address = address.slice(5);
            } else {
                prefix = 0;
            }
            buffer.writeUInt8 (address.length);
            buffer.writeUInt8 (prefix);
            buffer.writeUInt8 (include);
            buffer.writeUInt8 (0);  // reserved
            for ( let addressPart of address ) {
                buffer.writeUInt32BE (addressPart);
            }
        } else {
            buffer.writeUInt32BE (0);  // row of zeros for null OID
        }
    }

    static writeOctetString (buffer, octetString) {
        buffer.writeUInt32BE (octetString.length);
        buffer.writeString (octetString);
        var paddingOctets = ( 4 - octetString.length % 4 ) % 4;
        for ( let i = 0; i < paddingOctets ; i++ ) {
            buffer.writeUInt8 (0);
        }
    }

    static riteVarBind (buffer, varbind) {
        buffer.writeUInt16BE (varbind.type);
        buffer.writeUInt16BE (0); // reserved
        AgentXPdu.writeOid (buffer, varbind.oid);

        if (varbind.type && varbind.oid) {

            switch (varbind.type) {
                case ObjectType.Integer: // also Integer32
                case ObjectType.Counter: // also Counter32
                case ObjectType.Gauge: // also Gauge32 & Unsigned32
                case ObjectType.TimeTicks:
                    buffer.writeUInt32BE (varbind.value);
                    break;
                case ObjectType.OctetString:
                case ObjectType.Opaque:
                    AgentXPdu.writeOctetString (buffer, varbind.value);
                    break;
                case ObjectType.OID:
                    AgentXPdu.writeOid (buffer, varbind.value);
                    break;
                case ObjectType.IpAddress:
                    var bytes = varbind.value.split (".");
                    if (bytes.length != 4)
                        throw new RequestInvalidError ("Invalid IP address '"
                                + varbind.value + "'");
                    buffer.writeOctetString (buffer, Buffer.from (bytes));
                    break;
                case ObjectType.Counter64:
                    buffer.writeUint64 (varbind.value);
                    break;
                case ObjectType.Null:
                case ObjectType.EndOfMibView:
                case ObjectType.NoSuchObject:
                case ObjectType.NoSuchInstance:
                    break;
                default:
                    // Unknown data type - should never happen as the above covers all types in RFC 2741 Section 5.4
                    throw new RequestInvalidError ("Unknown type '" + varbind.type
                            + "' in request");
            }
        }
    }

    static writeVarbinds (buffer, varbinds) {
        if ( varbinds ) {
            for ( var i = 0; i < varbinds.length ; i++ ) {
                var varbind = varbinds[i];
                AgentXPdu.writeVarBind(buffer, varbind);
            }
        }
    }

    static readOid (buffer) {
        var subidLength = buffer.readUInt8 ();
        var prefix = buffer.readUInt8 ();
        var include = buffer.readUInt8 ();
        buffer.readUInt8 ();  // reserved

        // Null OID check
        if ( subidLength == 0 && prefix == 0 && include == 0) {
            return null;
        }
        var address = [];
        if ( prefix == 0 ) {
            address = [];
        } else {
            address = [1, 3, 6, 1, prefix];
        }
        for ( let i = 0; i < subidLength; i++ ) {
            address.push (buffer.readUInt32BE ());
        }
        var oid = address.join ('.');
        return oid;
    }

    static readSearchRange (buffer) {
        return {
            start: AgentXPdu.readOid (buffer),
            end: AgentXPdu.readOid (buffer)
        };
    }

    static readSearchRangeList (buffer, payloadLength) {
        var bytesLeft = payloadLength;
        var bufferPosition = (buffer.readOffset + 1);
        var searchRangeList = [];
        while (bytesLeft > 0) {
            searchRangeList.push (AgentXPdu.readSearchRange (buffer));
            bytesLeft -= (buffer.readOffset + 1) - bufferPosition;
            bufferPosition = buffer.readOffset + 1;
        }
        return searchRangeList;
    }

    static readOctetString (buffer) {
        var octetStringLength = buffer.readUInt32BE ();
        var paddingOctets = ( 4 - octetStringLength % 4 ) % 4;
        var octetString = buffer.readString (octetStringLength);
        buffer.readString (paddingOctets);
        return octetString;
    }

    static readVarbind (buffer) {
        var vtype = buffer.readUInt16BE ();
        buffer.readUInt16BE ();  // reserved
        var oid = AgentXPdu.readOid (buffer);
        var value;

        switch (vtype) {
            case ObjectType.Integer:
            case ObjectType.Counter:
            case ObjectType.Gauge:
            case ObjectType.TimeTicks:
                value = buffer.readUInt32BE ();
                break;
            case ObjectType.OctetString:
            case ObjectType.IpAddress:
            case ObjectType.Opaque:
                value = AgentXPdu.readOctetString (buffer);
                break;
            case ObjectType.OID:
                value = AgentXPdu.readOid (buffer);
                break;
            case ObjectType.Counter64:
                value = readUint64 (buffer);
                break;
            case ObjectType.Null:
            case ObjectType.NoSuchObject:
            case ObjectType.NoSuchInstance:
            case ObjectType.EndOfMibView:
                value = null;
                break;
            default:
                // Unknown data type - should never happen as the above covers all types in RFC 2741 Section 5.4
                throw new RequestInvalidError ("Unknown type '" + vtype
                    + "' in varbind");
        }

        return {
            type: vtype,
            oid: oid,
            value: value
        };
    }

    static readVarbinds (buffer, payloadLength) {
        var bytesLeft = payloadLength;
        var bufferPosition = (buffer.readOffset + 1);
        var varbindList = [];
        while (bytesLeft > 0) {
            varbindList.push (AgentXPdu.readVarbind (buffer));
            bytesLeft -= (buffer.readOffset + 1) - bufferPosition;
            bufferPosition = buffer.readOffset + 1;
        }
        return varbindList;
    }

    static packetID = 1;
}


type SubagentOptions = {
    debug?: boolean;
    master?: string;
    masterPort?: number;
    timeout: number;
    description?: string;
}

export class Subagent
    extends EventEmitter
{
    mib: Mib;
    master: string;
    masterPort: number;
    timeout: number;
    descr: string;
    sessionID: number;
    transactionID: number;
    packetID: number;
    requestPdus: {};
    setTransactions: {};
    socket: Socket | undefined

    constructor (options: SubagentOptions) {
        DEBUG = options.debug ?? false;
        this.mib = new Mib ();
        this.master = options.master || 'localhost';
        this.masterPort = options.masterPort || 705;
        this.timeout = options.timeout || 0;
        this.descr = options.description || "Node net-snmp AgentX sub-agent";
        this.sessionID = 0;
        this.transactionID = 0;
        this.packetID = _generateId();
        this.requestPdus = {};
        this.setTransactions = {};
        this.socket = undefined
    }

    onClose (): void {
	    this.emit ("close");
    }

    onError (error: Error): void {
	    this.emit ("error", error);
    }

    getMib (): Mib {
	    return this.mib;
    }

    connectSocket (): void {
        var me = this;
        this.socket = new Socket ();
        this.socket.connect (this.masterPort, this.master, function () {
            debug ("Connected to '" + me.master + "' on port " + me.masterPort);
        });

        this.socket.on ("data", me.onMsg.bind (me));
        this.socket.on ("error", me.onError.bind (me));
        this.socket.on ("close", me.onClose.bind (me));
    }

    open (callback): void {
        var pdu = AgentXPdu.createFromVariables ({
            pduType: AgentXPduType.Open,
            timeout: this.timeout,
            oid: this.oid,
            descr: this.descr
        });
        this.sendPdu (pdu, callback);
    }

    close (callback) {
        var pdu = AgentXPdu.createFromVariables ({
            pduType: AgentXPduType.Close,
            sessionID: this.sessionID
        });
        this.sendPdu (pdu, callback);
    }

    registerProvider (provider, callback) {
        var pdu = AgentXPdu.createFromVariables ({
            pduType: AgentXPduType.Register,
            sessionID: this.sessionID,
            rangeSubid: 0,
            timeout: 5,
            priority: 127,
            oid: provider.oid
        });
        this.mib.registerProvider (provider);
        this.sendPdu (pdu, callback);
    }

    unregisterProvider (name, callback) {
        var provider = this.getProvider (name);
        var pdu = AgentXPdu.createFromVariables ({
            pduType: AgentXPduType.Unregister,
            sessionID: this.sessionID,
            rangeSubid: 0,
            priority: 127,
            oid: provider.oid
        });
        this.mib.unregisterProvider (name);
        this.sendPdu (pdu, callback);
    }

    registerProviders (providers, callback) {
        for (var provider of providers) {
            this.registerProvider (provider, callback);
        }
    }

    getProvider (name) {
	    return this.mib.getProvider (name);
    };

    getProviders () {
        return this.mib.getProviders ();
    }

    addAgentCaps (oid, descr, callback) {
        var pdu = AgentXPdu.createFromVariables ({
            pduType: AgentXPduType.AddAgentCaps,
            sessionID: this.sessionID,
            oid: oid,
            descr: descr
        });
        this.sendPdu (pdu, callback);
    }

    removeAgentCaps (oid, callback) {
        var pdu = AgentXPdu.createFromVariables ({
            pduType: AgentXPduType.RemoveAgentCaps,
            sessionID: this.sessionID,
            oid: oid
        });
        this.sendPdu (pdu, callback);
    }

    notify (typeOrOid, varbinds, callback) {
        varbinds = varbinds || [];

        if (typeof typeOrOid != "string") {
            typeOrOid = "1.3.6.1.6.3.1.1.5." + (typeOrOid + 1);
        }

        var pduVarbinds = [
            {
                oid: "1.3.6.1.2.1.1.3.0",
                type: ObjectType.TimeTicks,
                value: Math.floor (process.uptime () * 100)
            },
            {
                oid: "1.3.6.1.6.3.1.1.4.1.0",
                type: ObjectType.OID,
                value: typeOrOid
            }
        ];

        pduVarbinds = pduVarbinds.concat (varbinds);

        var pdu = AgentXPdu.createFromVariables ({
            pduType: AgentXPduType.Notify,
            sessionID: this.sessionID,
            varbinds: pduVarbinds
        });
        this.sendPdu (pdu, callback);
    }

    ping (callback) {
        var pdu = AgentXPdu.createFromVariables ({
            pduType: AgentXPduType.Ping,
            sessionID: this.sessionID
        });
        this.sendPdu (pdu, callback);
    }

    sendPdu (pdu: AgentXPdu, callback) {
        debug ("Sending AgentX " + AgentXPduType[pdu.pduType] + " PDU");
        debug (pdu);
        var buffer = pdu.toBuffer ();
        this.socket.write (buffer);
        if ( pdu.pduType != AgentXPduType.Response && ! this.requestPdus[pdu.packetID] ) {
            pdu.callback = callback;
            this.requestPdus[pdu.packetID] = pdu;
        }

        // Possible timeout / retry mechanism?
        // var me = this;
        // pdu.timer = setTimeout (function () {
        // 	if (pdu.retries-- > 0) {
        // 		this.sendPdu (pdu);
        // 	} else {
        // 		delete me.requestPdus[pdu.packetID];
        // 		me.callback (new RequestTimedOutError (
        // 				"Request timed out"));
        // 	}
        // }, this.timeout);

    }

    onMsg (buffer, rinfo) {
        var pdu = AgentXPdu.createFromBuffer (buffer);

        debug ("Received AgentX " + AgentXPduType[pdu.pduType] + " PDU");
        debug (pdu);

        switch (pdu.pduType) {
            case AgentXPduType.Response:
                this.response (pdu);
                break;
            case AgentXPduType.Get:
                this.getRequest (pdu);
                break;
            case AgentXPduType.GetNext:
                this.getNextRequest (pdu);
                break;
            case AgentXPduType.GetBulk:
                this.getBulkRequest (pdu);
                break;
            case AgentXPduType.TestSet:
                this.testSet (pdu);
                break;
            case AgentXPduType.CommitSet:
                this.commitSet (pdu);
                break;
            case AgentXPduType.UndoSet:
                this.undoSet (pdu);
                break;
            case AgentXPduType.CleanupSet:
                this.cleanupSet (pdu);
                break;
            default:
                // Unknown PDU type - shouldn't happen as master agents shouldn't send administrative PDUs
                throw new RequestInvalidError ("Unknown PDU type '" + pdu.pduType
                        + "' in request");
        }
    }

    response (pdu) {
        var requestPdu = this.requestPdus[pdu.packetID];
        if (requestPdu) {
            delete this.requestPdus[pdu.packetID];
            // clearTimeout (pdu.timer);
            // delete pdu.timer;
            switch (requestPdu.pduType) {
                case AgentXPduType.Open:
                    this.sessionID = pdu.sessionID;
                    break;
                case AgentXPduType.Close:
                    this.socket.end();
                    break;
                case AgentXPduType.Register:
                case AgentXPduType.Unregister:
                case AgentXPduType.AddAgentCaps:
                case AgentXPduType.RemoveAgentCaps:
                case AgentXPduType.Notify:
                case AgentXPduType.Ping:
                    break;
                default:
                    // Response PDU for request type not handled
                    throw new ResponseInvalidError ("Response PDU for type '" + requestPdu.pduType + "' not handled",
                            ResponseInvalidCode.EResponseNotHandled);
            }
            if (requestPdu.callback) {
                requestPdu.callback(null, pdu);
            }
        } else {
            // unexpected Response PDU - has no matching request
            throw new ResponseInvalidError ("Unexpected Response PDU with packetID " + pdu.packetID,
                    ResponseInvalidCode.EUnexpectedResponse);
        }
    }

    request (pdu, requestVarbinds) {
        var me = this;
        var varbindsCompleted = 0;
        var varbindsLength = requestVarbinds.length;
        var responseVarbinds = [];

        for ( var i = 0; i < requestVarbinds.length; i++ ) {
            var requestVarbind = requestVarbinds[i];
            var instanceNode = this.mib.lookup (requestVarbind.oid);
            var providerNode;
            var mibRequest;
            var handler;
            var responseVarbindType;

            if ( ! instanceNode ) {
                mibRequest = new MibRequest ({
                    operation: pdu.pduType,
                    oid: requestVarbind.oid
                });
                handler = function getNsoHandler (mibRequestForNso) {
                    mibRequestForNso.done ({
                        errorStatus: ErrorStatus.NoError,
                        errorIndex: 0,
                        type: ObjectType.NoSuchObject,
                        value: null
                    });
                };
            } else {
                providerNode = this.mib.getProviderNodeForInstance (instanceNode);
                if ( ! providerNode ) {
                    mibRequest = new MibRequest ({
                        operation: pdu.pduType,
                        oid: requestVarbind.oid
                    });
                    handler = function getNsiHandler (mibRequestForNsi) {
                        mibRequestForNsi.done ({
                            errorStatus: ErrorStatus.NoError,
                            errorIndex: 0,
                            type: ObjectType.NoSuchInstance,
                            value: null
                        });
                    };
                } else {
                    mibRequest = new MibRequest ({
                        operation: pdu.pduType,
                        providerNode: providerNode,
                        instanceNode: instanceNode,
                        oid: requestVarbind.oid
                    });
                    if ( pdu.pduType == AgentXPduType.TestSet ) {
                        mibRequest.setType = requestVarbind.type;
                        mibRequest.setValue = requestVarbind.value;
                    }
                    handler = providerNode.provider.handler;
                }
            }

            (function (savedIndex) {
                var responseVarbind;
                mibRequest.done = function (error) {
                    if ( error ) {
                        responseVarbind = {
                            oid: mibRequest.oid,
                            type: error.type || ObjectType.Null,
                            value: error.value || null
                        };
                    } else {
                        if ( pdu.pduType == AgentXPduType.TestSet ) {
                            // more tests?
                        } else if ( pdu.pduType == AgentXPduType.CommitSet ) {
                            me.setTransactions[pdu.transactionID].originalValue = mibRequest.instanceNode.value;
                            mibRequest.instanceNode.value = requestVarbind.value;
                        } else if ( pdu.pduType == AgentXPduType.UndoSet ) {
                            mibRequest.instanceNode.value = me.setTransactions[pdu.transactionID].originalValue;
                        }
                        if ( ( pdu.pduType == AgentXPduType.GetNext || pdu.pduType == AgentXPduType.GetBulk ) &&
                                requestVarbind.type == ObjectType.EndOfMibView ) {
                            responseVarbindType = ObjectType.EndOfMibView;
                        } else {
                            responseVarbindType = mibRequest.instanceNode.valueType;
                        }
                        responseVarbind = {
                            oid: mibRequest.oid,
                            type: responseVarbindType,
                            value: mibRequest.instanceNode.value
                        };
                    }
                    responseVarbinds[savedIndex] = responseVarbind;
                    if ( ++varbindsCompleted == varbindsLength) {
                        if ( pdu.pduType == AgentXPduType.TestSet || pdu.pduType == AgentXPduType.CommitSet
                                || pdu.pduType == AgentXPduType.UndoSet) {
                            me.sendSetResponse.call (me, pdu);
                        } else {
                            me.sendGetResponse.call (me, pdu, responseVarbinds);
                        }
                    }
                };
            })(i);
            if ( handler ) {
                handler (mibRequest);
            } else {
                mibRequest.done ();
            }
        }
    }

    addGetNextVarbind (targetVarbinds, startOid) {
        var startNode;
        var getNextNode;

        try {
            startNode = this.mib.lookup (startOid);
        } catch ( error ) {
            startOid = '1.3.6.1';
            startNode = this.mib.lookup (startOid);
        }

        if ( ! startNode ) {
            // Off-tree start specified
            startNode = this.mib.getTreeNode (startOid);
        }
        getNextNode = startNode.getNextInstanceNode();
        if ( ! getNextNode ) {
            // End of MIB
            targetVarbinds.push ({
                oid: startOid,
                type: ObjectType.EndOfMibView,
                value: null
            });
        } else {
            // Normal response
            targetVarbinds.push ({
                oid: getNextNode.oid,
                type: getNextNode.valueType,
                value: getNextNode.value
            });
        }

        return getNextNode;
    }

    getRequest (pdu) {
        var requestVarbinds = [];

        for ( var i = 0; i < pdu.searchRangeList.length; i++ ) {
            requestVarbinds.push ({
                oid: pdu.searchRangeList[i].start,
                value: null,
                type: null
            });
        }
        this.request (pdu, requestVarbinds);
    }

    getNextRequest (pdu) {
        var getNextVarbinds = [];

        for (var i = 0 ; i < pdu.searchRangeList.length ; i++ ) {
            this.addGetNextVarbind (getNextVarbinds, pdu.searchRangeList[i].start);
        }

        this.request (pdu, getNextVarbinds);
    }

    getBulkRequest (pdu) {
        var getBulkVarbinds = [];
        var startOid = [];
        var getNextNode;
        var endOfMib = false;

        for (var n = 0 ; n < pdu.nonRepeaters ; n++ ) {
            this.addGetNextVarbind (getBulkVarbinds, pdu.searchRangeList[n].start);
        }

        for (var v = pdu.nonRepeaters ; v < pdu.searchRangeList.length ; v++ ) {
            startOid.push (pdu.searchRangeList[v].oid);
        }

        while ( getBulkVarbinds.length < pdu.maxRepetitions && ! endOfMib ) {
            for (var w = pdu.nonRepeaters ; w < pdu.searchRangeList.length ; w++ ) {
                if (getBulkVarbinds.length < pdu.maxRepetitions ) {
                    getNextNode = this.addGetNextVarbind (getBulkVarbinds, startOid[w - pdu.nonRepeaters]);
                    if ( getNextNode ) {
                        startOid[w - pdu.nonRepeaters] = getNextNode.oid;
                        if ( getNextNode.type == ObjectType.EndOfMibView ) {
                            endOfMib = true;
                        }
                    }
                }
            }
        }

        this.request (pdu, getBulkVarbinds);
    }

    sendGetResponse = function (requestPdu, varbinds) {
        var pdu = AgentXPdu.createFromVariables ({
            pduType: AgentXPduType.Response,
            sessionID: requestPdu.sessionID,
            transactionID: requestPdu.transactionID,
            packetID: requestPdu.packetID,
            sysUpTime: 0,
            error: 0,
            index: 0,
            varbinds: varbinds
        });
        this.sendPdu (pdu, null);
    }

    sendSetResponse (setPdu) {
        var responsePdu = AgentXPdu.createFromVariables ({
            pduType: AgentXPduType.Response,
            sessionID: setPdu.sessionID,
            transactionID: setPdu.transactionID,
            packetID: setPdu.packetID,
            sysUpTime: 0,
            error: 0,
            index: 0,
        });
        this.sendPdu (responsePdu, null);
    }

    testSet (setPdu) {
        this.setTransactions[setPdu.transactionID] = setPdu;
        this.request (setPdu, setPdu.varbinds);
    }

    commitSet (setPdu) {
        if ( this.setTransactions[setPdu.transactionID] ) {
            this.request (setPdu, this.setTransactions[setPdu.transactionID].varbinds);
        } else {
            throw new RequestInvalidError ("Unexpected CommitSet PDU with transactionID " + setPdu.transactionID);
        }
    }

    undoSet (setPdu) {
        if ( this.setTransactions[setPdu.transactionID] ) {
            this.request (setPdu, this.setTransactions[setPdu.transactionID].varbinds);
        } else {
            throw new RequestInvalidError ("Unexpected UndoSet PDU with transactionID " + setPdu.transactionID);
        }
    }

    cleanupSet = function (setPdu) {
        if ( this.setTransactions[setPdu.transactionID] ) {
            delete this.setTransactions[setPdu.transactionID];
        } else {
            throw new RequestInvalidError ("Unexpected CleanupSet PDU with transactionID " + setPdu.transactionID);
        }
    }

    static create (options) {
        var subagent = new Subagent (options);
        subagent.connectSocket ();
        return subagent;
    }
}


/*****************************************************************************
 ** Exports
 **/

export const createSession = Session.create;
export const createV3Session = Session.createV3;

export const createReceiver = Receiver.create;
export const createAgent = Agent.create;
export const createModuleStore = ModuleStore.create;
export const createSubagent = Subagent.create;
export const createMib = Mib.create;

export const ObjectParser = {
	readInt32: readInt32,
	readUint32: readUint32,
	readVarbindValue: readVarbindValue
};
