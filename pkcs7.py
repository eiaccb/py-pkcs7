#!/usr/bin/env python

# Handle pkcs7 data in ways that pyca cannot right now
# As much as possible, support form pyca has been used

# Standard packages
import sys
import logging
logger = logging.getLogger(__name__)

import base64
from binascii import hexlify
from struct import unpack
import getpass
import hashlib

# Contributed packages
import asn1
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import serialization

# 16, 32, 0
universal_sequence = asn1.Tag(
    asn1.Numbers.Sequence,
    asn1.Types.Constructed,
    asn1.Classes.Universal)

# 17, 32, 0
universal_set = asn1.Tag(
    asn1.Numbers.Set,
    asn1.Types.Constructed,
    asn1.Classes.Universal)

# 2, 0, 0
universal_integer = asn1.Tag(
    asn1.Numbers.Integer,
    asn1.Types.Primitive,
    asn1.Classes.Universal)

# 4, 0, 0
universal_octetstring = asn1.Tag(
    asn1.Numbers.OctetString,
    asn1.Types.Primitive,
    asn1.Classes.Universal)
normal_octetstring = universal_octetstring

# 6, 0, 0
universal_oid = asn1.Tag(
    asn1.Numbers.ObjectIdentifier,
    asn1.Types.Primitive,
    asn1.Classes.Universal)

# 12, 0, 0
universal_utf8string = asn1.Tag(
    asn1.Numbers.UTF8String,
    asn1.Types.Primitive,
    asn1.Classes.Universal)

# 22, 0, 0
universall_ia5string = asn1.Tag(
    asn1.Numbers.IA5String,
    asn1.Types.Primitive,
    asn1.Classes.Universal)

# 23, 0, 0
universal_utctime = asn1.Tag(
    asn1.Numbers.UTCTime,
    asn1.Types.Primitive,
    asn1.Classes.Universal)

# 0, 32, 128
context_any0 = asn1.Tag(
    0,
    asn1.Types.Constructed,
    asn1.Classes.Context)

# 1, 32, 128
context_any1 = asn1.Tag(
    1,
    asn1.Types.Constructed,
    asn1.Classes.Context)

Data_OID = '1.2.840.113549.1.7.1'
SignedData_OID = '1.2.840.113549.1.7.2'

SPC_INDIRECT_DATA_OBJID = '1.3.6.1.4.1.311.2.1.4'
SPC_HASH_INFO_OBJID = x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.29')
SigFormatDescriptorV1_OID = x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.31')

SpcIndirectDataContent_OID = '1.3.6.1.4.1.311.2.1.4'

def get_decoder(decoder, data):
    if decoder:
        return decoder
    if data:
        decoder = MyDecoder()
        decoder.start(data)
        return decoder
    else:
        raise ValueError("No data")

# When handling something that is already ASN.1 and we want to icnclude in
# a strucuture, the API has no provision for this, so we use
# read to the V from the TLV triad, so we can later insert it with
# encoder.write()
def peel(value):
    decoder = asn1.Decoder()
    decoder.start(value)
    return decoder.read()

class MyDecoder(asn1.Decoder):

    # This abuses the internal implementation of module asn1. FIXME.
    def current_length(self, adjust=0):
        current_frame = self.m_stack[-1]
        # return len(current_frame[1]) - current_frame[0]
        return len(current_frame[1]) - adjust

    # This abuses the internal implementation of module asn1. FIXME.
    def current_buffer(self):
        current_frame = self.m_stack[-1]
        return current_frame[1][current_frame[0]-1:]

    def read_raw(self):
        tag, val = self.read()
        encoder = asn1.Encoder()
        encoder.start()
        encoder.write(val, nr=tag.nr, typ=tag.typ, cls=tag.cls)
        return tag, encoder.output()

oidnames = {
    '1.2.840.113549.1.7.2': 'SignedData',
    '1.2.840.113549.1.1.1': 'rsaEncryption',
    '1.2.840.113549.2.5': 'md5',
    '1.3.6.1.4.1.311.2.1.4': 'SpcIndirectDataContent',
    '1.3.6.1.4.1.311.2.1.31': 'SpcIndirectDataContentV2',
    '2.16.840.1.101.3.4.2.3': 'sha512',
}

attr_types = {
    '0.9.2342.19200300.100.1.25': [['dc', 'domainComponent'], NameOID.DOMAIN_COMPONENT],
    '1.2.840.113549.1.9.3': [['contentType'], x509.ObjectIdentifier('1.2.840.113549.1.9.3')],
    '1.2.840.113549.1.9.4': [['messageDigest'], x509.ObjectIdentifier('1.2.840.113549.1.9.4')],
    '1.3.6.1.4.1.311.2.1.4': [['SPC_INDIRECT_DATA_OBJID'], x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.4')],
    '1.3.6.1.4.1.311.2.1.11': [['SPC_STATEMENT_TYPE_OBJID'], x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.11')],
    '1.3.6.1.4.1.311.2.1.12': [['SPC_SP_OPUS_INFO_OBJID'], x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.12')],
    '1.3.6.1.4.1.311.2.1.29': [['SPC_HASH_INFO_OBJID'], x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.29')],
    '1.3.6.1.4.1.311.2.1.31': [['SigFormatDescriptorV1'], x509.ObjectIdentifier('1.3.6.1.4.1.311.2.1.31')],
    '2.5.4.3': [['cn','commonName'], NameOID.COMMON_NAME],
}
def oid2name(oid):
    if oid in oidnames:
        return "%s: %s" % (oid, oidnames[oid])
    else:
        return "%s: (unknown)" % (oid,)

def attr_type(oid):
    if oid in attr_types:
        return attr_types[oid][0][0]
    else:
        return oid

class ASN1Error(Exception):
    pass

def SequenceOf(cls, decoder=None, data=None):
    obj = []
    decoder = get_decoder(decoder, data)
    logger.debug("SequenceOf %s: %d bytes pending" % (cls, decoder.current_length()))

    tag = decoder.peek()
    if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})
    decoder.enter()
    tag = decoder.peek()
    while tag:
        element = cls.parse(decoder)
        obj.append(element)
        tag = decoder.peek()
    decoder.leave()

    return obj

def SetOf(cls, decoder=None, data=None, expect=None):
    if not expect:
        expect = universal_set 
    obj = set()
    decoder = get_decoder(decoder, data)
    logger.debug("SetOf %s: %d bytes pending" % (cls, decoder.current_length()))

    tag = decoder.peek()
    if tag != expect:
        raise ASN1Error({'expected': expect, 'found': tag})
    decoder.enter()
    tag = decoder.peek()
    while tag:
        element = cls.parse(decoder)
        obj.add(element)
        tag = decoder.peek()
    decoder.leave()

    return obj

def get_universal_integer(decoder):
    tag, val = decoder.read()
    if tag != universal_integer:
        raise ASN1Error({'expected': universal_integer, 'found': tag})
    return val

def get_universal_octetstring(decoder):
    tag, val = decoder.read()
    if tag != universal_octetstring:
        raise ASN1Error({'expected': universal_octetstring, 'found': tag})
    return val

def get_universal_oid(decoder):
    tag, val = decoder.read()
    if tag != universal_oid:
        raise ASN1Error({'expected': universal_oid, 'found': tag})
    return x509.ObjectIdentifier(val)

def load_certificate(path):
    certificate_bytes = open(path, 'rb').read()
    if b'--BEGIN CERTIFICATE--' in certificate_bytes:
        cert = x509.load_pem_x509_certificate(certificate_bytes)
    else:
        cert = x509.load_der_x509_certificate(certificate_bytes)
    return cert

class SignerEngine():

    def sign(self, data):
        raise NotImplementedError("Missing sign implemantarion")
    
class PrivateKeySignerEngine(SignerEngine):

    def __init__(self, path, password=None):
        data = open(path, 'rb').read()
        self.private_key = serialization.load_pem_private_key(data, password)

    def sign(self, data, padding=padding.PKCS1v15(), algorithm=Prehashed):
        logger.debug(data)
        result = self.private_key.sign(data, padding, algorithm)
        return result

# TODO: The following classes are not generic enough.
# Possibly move them elsewhere

# SpcIndirectDataContent ::= SEQUENCE {
#     data               SpcAttributeTypeAndOptionalValue,
#     messageDigest      DigestInfo
# }
  
class SpcIndirectDataContent:

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)
        logger.debug("SpcIndirectDataContent: %d bytes pending" % decoder.current_length())

        tag = decoder.peek()
        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})

        decoder.enter()
        obj.data = SpcAttributeTypeAndOptionalValue.parse(decoder)
        obj.messageDigest = DigestInfo.parse(decoder)
        logger.info("messageDigest: %s" % hexlify(obj.messageDigest.digest))
        logger.debug(obj.messageDigest)

        if obj.data.type == SPC_HASH_INFO_OBJID:
            pass
        elif obj.data.type == SigFormatDescriptorV1_OID:
            obj.messageDigest.zoom_in(SigDataV1Serialized)
        decoder.leave()

        return obj

# SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
#     type                OBJECT IDENTIFIER,
#     value               [0] EXPLICIT ANY OPTIONAL
# }
  
class SpcAttributeTypeAndOptionalValue:

    def __str__(self):
        return "%s: %s" % (attr_type(self.type.dotted_string), hexlify(self.value))

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)

        logger.debug("SpcAttributeTypeAndOptionalValue: %d bytes pending" % decoder.current_length())
        tag = decoder.peek()
        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})

        decoder.enter()

        tag, val = decoder.read()
        if tag != universal_oid:
            raise ASN1Error({'expected': universal_oid, 'found': tag})

        obj.type = x509.ObjectIdentifier(val)
        logger.debug("Type is %s" % oid2name(obj.type))

        tag = decoder.peek()
        if tag != normal_octetstring:
            raise ASN1Error({'expected': normal_octetstring, 'found': tag})

        if obj.type == SPC_HASH_INFO_OBJID:
            tag, val = decoder.read()
            obj.value = val
        elif obj.type == SigFormatDescriptorV1_OID:
            tag, val = decoder.read()
            logger.debug("Tag=%s Length=%d, raw=%s" % (tag, len(val), hexlify(val)))
            obj.value = SigFormatDescriptorV1.parse(data=val)
        else:
            raise ValueError("Unexpected type for SpcAttributeTypeAndOptionalValue")
        
        logger.debug(tag)
        obj.value = val

        decoder.leave()

        return obj

# SigFormatDescriptorV1 ::= SEQUENCE {
#      size               INTEGER,
#      version            INTEGER,
#      format             INTEGER
# }

class SigFormatDescriptorV1:

    def __str__(self):
        return "%s: %s" % (attr_type(self.type.dotted_string), hexlify(self.value))

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        # Supposedly:
        # The value field MUST be an OCTETSTRING ([ITUX680-1994] section 20). The value MUST contain the DER encoding ASN.1 data of a SigFormatDescriptorV1 structure.
        # This is NOT true. It is just a concatenation of the three fields
        # Length is 12 (0x0C) so any attemopt to parse it as DER will
        # detect a bogus UTF8String

        logger.debug("Data len = %d" % len(data))
        if data and len(data) == 12 and data[0] == 0x0C:
            (obj.size,
             obj.version,
             obj.format) = unpack('<LLL', data)
            return obj

        # Otherwise, let's try what the spec says
        decoder = get_decoder(decoder, data)

        tag = decoder.peek()
        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})

        decoder.enter()

        tag, val = decoder.read()
        if tag != universal_integer:
            raise ASN1Error({'expected': universal_integer, 'found': tag})
        obj.size = val

        tag, val = decoder.read()
        if tag != universal_integer:
            raise ASN1Error({'expected': universal_integer, 'found': tag})
        obj.version = val

        tag, val = decoder.read()
        if tag != universal_integer:
            raise ASN1Error({'expected': universal_integer, 'found': tag})
        obj.format = val

        decoder.leave()

# SigDataV1Serialized ::= SEQUENCE {
#     algorithmIdSize    INTEGER,
#     compiledHashSize   INTEGER,
#     sourceHashSize     INTEGER,
#     algorithmIdOffset  INTEGER,
#     compiledHashOffset INTEGER,
#     sourceHashOffset   INTEGER,
#     algorithmId        OBJECT IDENTIFIER,
#     compiledHash
#     sourceHash         OCTETSTRING
# }

class SigDataV1Serialized:
    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()

        if data:
            logger.debug("SigDataV1Serialized: (%d): %s" % (len(data), hexlify(data)))
            # Another one that is supposedly DER, but isn't
            (obj.algorithmIdSize,
             obj.compiledHashSize,
             obj.sourceHashSize,
             obj.algorithmIdOffset,
             obj.compiledHashOffset,
             obj.sourceHashOffset) = unpack('<LLLLLL', data[:24])

            total_length = 24 + obj.algorithmIdSize + obj.compiledHashSize + obj.sourceHashSize
            if total_length != len(data):
                raise ValueError("Length of SigDataV1Serialized should be %d, but the buffer is %d" % (total_length, len(data)))

            if obj.sourceHashOffset + obj.sourceHashSize != len(data):
                raise ValueError("sourceHash is not at the end")
            # And don't miss this, the digest algorithm OID as a null
            # terminated ASCII string!!!
            algorithmId = data[obj.algorithmIdOffset:obj.algorithmIdOffset+obj.algorithmIdSize]
            obj.algorithmId = x509.ObjectIdentifier(algorithmId.decode('ascii').rstrip('\0'))
            logger.debug('%002x: %002x algorithmId: %s' % (obj.algorithmIdOffset, obj.algorithmIdSize, obj.algorithmId))
            obj.compiledHash = data[obj.compiledHashOffset:obj.compiledHashOffset+obj.compiledHashSize]
            logger.debug('%002x: %002x compiledHash: %s' % (obj.compiledHashOffset, obj.compiledHashSize, hexlify(obj.compiledHash)))
            obj.sourceHash = data[obj.sourceHashOffset:obj.sourceHashOffset+obj.sourceHashSize]
            logger.debug('%002x: %002x sourceHash: %s' % (obj.sourceHashOffset, obj.sourceHashSize, hexlify(obj.sourceHash)))
                
            return obj

        # Otherwise, let's try what the spec says
        decoder = get_decoder(decoder, data)

        tag = decoder.peek()
        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})
        decoder.enter()

        obj.algorithmIdSize = get_universal_imteger(decoder)
        obj.compiledHashSize = get_universal_imteger(decoder)
        obj.sourceHashSize = get_universal_imteger(decoder)
        obj.algorithmIdOffset = get_universal_imteger(decoder)
        obj.compiledHashOffset = get_universal_imteger(decoder)
        obj.sourceHashOffset = get_universal_imteger(decoder)
        obj.algorithmId = get_universal_oid(decoder)
        # The specification recommends leaving compiledHash
        # We don't even know what that is supposed to mean
        obj.compiledHash = get_universal_octetstring(decoder)
        obj.sourceHash = get_universal_octetstring(decoder)

        decoder.leave()

class ASN1Data:

    def as_der_bytes(self):
        encoder = asn1.Encoder()
        encoder.start()
        self.asn1_serialize(encoder)
        return encoder.output()


# Defined in X.509

# Name            ::=   CHOICE { -- only one possibility for now --
#                                  rdnSequence  RDNSequence }
# RDNSequence     ::=   SEQUENCE OF RelativeDistinguishedName
# DistinguishedName       ::=   RDNSequence
class Name:

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        obj.rdnSequence = SequenceOf(RelativeDistinguishedName, decoder, data)
        # print(obj.rdnSequence)
        # Funny, it wants a pure sequence without sets
        # obj.name = x509.Name(obj.rdnSequence)
        nl = []
        for rdn in obj.rdnSequence:
            for element in rdn:
                nl.append(element)
        obj.name = x509.Name(nl)
        return obj

        decoder = get_decoder(decoder, data)

        tag = decoder.peek()
        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})

        rdns = []

        logger.debug(tag)
        logger.debug("Name: %s pending (%s)" % (decoder.current_length(), hexlify(decoder.current_buffer()[:32])))

        decoder.enter()
        seq_tag = decoder.peek()
        while seq_tag:
            logger.debug(seq_tag)
            logger.debug("Name one RDN: %s pending (%s)" % (decoder.current_length(), hexlify(decoder.current_buffer()[:32])))
            rdn = set()
            decoder.enter()
            set_tag = decoder.peek()
            while set_tag:
                logger.debug(set_tag)
                logger.debug("Name one RDN element: %s pending (%s)" % (decoder.current_length(), hexlify(decoder.current_buffer()[:32])))
                decoder.enter()
                tag, val = decoder.read()
                if tag != universal_oid:
                    raise ASN1Error({'expected': universal_oid, 'found': tag})
                oid = val
                tag, val = decoder.read()
                logger.debug("Name one RDN element %s=%s" % (attr_type(oid), val))
                rdns.append(x509.NameAttribute(x509.ObjectIdentifier(oid), val))
                
                decoder.leave()
                set_tag = decoder.peek()
            decoder.leave()
            seq_tag = decoder.peek()
        decoder.leave()

        logger.debug(rdns)
        name = x509.Name(rdns)

        logger.debug(name.rfc4514_string())
        return name

    def asn1_serialize(self, encoder):
        name_der__bytes = self.public_bytes()
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(peel(name_der_bytes)[1], asn1.Numbers.Sequence. asn1.TYpes.Constructed)
        encoder.leave()
        
# RelativeDistinguishedName  ::=
#                    SET SIZE (1 .. MAX) OF AttributeTypeAndValue
class RelativeDistinguishedName:

    @classmethod
    def parse(cls, decoder=None, data=None):
        rdn = SetOf(AttributeTypeAndValue, decoder, data)
        return rdn

class AttributeTypeAndValue:

    @classmethod
    def parse(cls, decoder=None, data=None):
        decoder = get_decoder(decoder, data)

        logger.debug("AttributeTypeAndValue: %d bytes pending" % decoder.current_length())
        tag = decoder.peek()
        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})

        decoder.enter()
        tag, val = decoder.read()
        if tag != universal_oid:
            raise ASN1Error({'expected': universal_oid, 'found': tag})
        oid = x509.ObjectIdentifier(val)
        tag, val = decoder.read()
        logger.debug("AttributeTypeAndValue %s=%s" % (attr_type(oid.dotted_string), val))
        decoder.leave()

        atv = x509.NameAttribute(oid, val)
        return atv

# Defined in X.509  
# AlgorithmIdentifier ::= SEQUENCE {
#     algorithm          OBJECT IDENTIFIER,
#     parameters         [0] EXPLICIT ANY OPTIONAL
# }

class AlgorithmIdentifier:

    def __str__(self):
        return "Algorithm %s (%s)" % (
            oid2name(self.algorithm.dotted_string),
            self.parameters)

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)
        decoder.enter()
        tag, val = decoder.read()
        if tag != universal_oid:
            raise ASN1Error({'expected': universal_oid, 'found': tag})
        oid = val
        obj.algorithm = x509.ObjectIdentifier(oid)
        tag, val = decoder.read()
        obj.parameters = val
        logger.debug("DigestAlgorithm: %s, params: %s" % (oid2name(oid), obj.parameters))
        decoder.leave()

        return obj

    algorithm_table = {
        'sha256': '2.16.840.1.101.3.4.2.1',
        'rsaencryption': '1.2.840.113549.1.1.1',
    }

    @classmethod
    def build(cls, name=None, oid=None, parameters=None):
        obj = cls()
        if not oid:
            oid = cls.algorithm_table.get(name.lower(), None)
        if not oid:
            raise ValueError("The algorithm {} was not understood".format(name))

        if parameters:
            raise NotImplementedError("Parameters on algorithms is not supported yet")

        if isinstance(oid, x509.ObjectIdentifier):
            obj.algorithm = oid
        else:
            obj.algorithm = x509.ObjectIdentifier(oid)
        obj.parameters = None

        return obj

    def asn1_serialize(self, encoder):
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(self.algorithm.dotted_string, asn1.Numbers.ObjectIdentifier)
        # parameters not suported yet
        if self.parameters:
            raise NotImplementedError('Parameters in algorithms are not supported yet')
        else:
            encoder.write(None, asn1.Numbers.Null)
        encoder.leave()

# Three columns: Common name, cryptography hash function, hashlib function
digest_algorithms_by_oid = {
    '1.2.840.113549.2.5': ['MD5', hashes.MD5, hashlib.md5],
    '2.16.840.1.101.3.4.2.1': ['SHA256', hashes.SHA256, hashlib.sha256],
    '2.16.840.1.101.3.4.2.3': ['sha512', hashes.SHA512, hashlib.sha512],
}

digest_algorithms_by_name = {
    'md5': ['1.2.840.113549.2.5', hashes.MD5, hashlib.md5],
    'sha256': ['2.16.840.1.101.3.4.2.1',  hashes.SHA256, hashlib.sha256],
    'sha512': ['2.16.840.1.101.3.4.2.3',  hashes.SHA512, hashlib.sha512],
}
        
class DigestAlgorithmIdentifier(AlgorithmIdentifier):

    def compute(self, data):
        oid = self.algorithm.dotted_string
        if oid in digest_algorithms_by_oid:
            logger.debug(data)
            digest = digest_algorithms_by_oid[oid][2](data)
        else:
            raise NotImplementedError("No implementation for {}".format(oid))

        return digest

class DigestEncryptionAlgorithmIdentifier(AlgorithmIdentifier):
    pass

class DigestAlgorithms:
    def __init__(self):
        self.algorithms = set()

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)
        logger.debug("DigestAlgorithms: %d bytes pending" % decoder.current_length())

        decoder.enter()
        tag = decoder.peek()
        while tag:
            obj.algorithms.add(DigestAlgorithmIdentifier.parse(decoder))
            tag = decoder.peek()
        decoder.leave()

        return obj

# From PKCS #9, 5.3 Attribute types to be used in PKCS #7 data
# We define here a couple of classes to hold values for the
# contentType and messageDigest Attributes 
class PKCS9_ContentType:
    def __init__(self, value):
        if isinstance(value, x509.ObjectIdentifier):
            self.oid = value
        else:
            self.oid = x509.ObjectIdentifier(value)

    def asn1_serialize(self, encoder):
        encoder.write(self.oid.dotted_string, asn1.Numbers.ObjectIdentifier)

class PKCS9_MessageDigest:
    def __init__(self, value):
        if isinstance(value, (str, bytes)):
            self.messageDigest = value
        else:
            self.messageDigest = value.digest

    def asn1_serialize(self, encoder):
        encoder.write(self.messageDigest, asn1.Numbers.OctetString)
        
# Attribute       ::=     SEQUENCE {
#   type            AttributeType,
#   values  SET OF AttributeValue
#           -- at least one value is required -- }
class Attribute:

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)
        logger.debug("Attribute: %s pending (%s)" % (decoder.current_length(), hexlify(decoder.current_buffer()[:32])))

        tag = decoder.peek()
        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})

        decoder.enter()

        tag, val = decoder.read()
        if tag != universal_oid:
            raise ASN1Error({'expected': universal_oid, 'found': tag})
        obj.type = val

        obj.values = set()
        tag = decoder.peek()
        if tag != universal_set:
            raise ASN1Error({'expected': universal_set, 'found': tag})
        decoder.enter()
        tag = decoder.peek()
        while tag:
            tag, val = decoder.read()
            logger.debug("Attribute value %s=%s" % (attr_type(obj.type), val))
            obj.values.add(val)
            tag = decoder.peek()
        decoder.leave()

        decoder.leave()

    @classmethod
    def build(cls, typ, values):
        obj = cls()
        obj.type = typ
        obj.values = values
        return obj

    def asn1_serialize(self, encoder):
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(self.type.dotted_string, asn1.Numbers.ObjectIdentifier)
        encoder.enter(asn1.Numbers.Set)
        for v in self.values:
            try:
                v.asn1_serialize(encoder)
            except (AssertionError, AttributeError, TypeError):
                logger.error("Problem serializing {}".format(v))
                raise
        encoder.leave()
        encoder.leave()

class Attributes:

    def __init__(self):
        # Actually should be a set, we use a list to simplify debugging
        # by comparison with samples
        self.attributes = []

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)
        logger.debug("Attributes: %s pending (%s)" % (decoder.current_length(), hexlify(decoder.current_buffer()[:32])))

        decoder.enter()
        tag = decoder.peek()
        while tag:
            obj.attributes.append(Attribute.parse(decoder))
            tag = decoder.peek()
        decoder.leave()

        return obj

    def add_attribute(self, attribute):
        if not attribute in self.attributes:
            self.attributes.append(attribute)

    def asn1_serialize(self, encoder, tag=None):
        if tag is None:
            encoder.enter(asn1.Numbers.Set)
        else:
            encoder.enter(tag, asn1.Classes.Context)
        for attribute in self.attributes:
            attribute.asn1_serialize(encoder)
        encoder.leave()

# 6.6 ExtendedCertificatesAndCertificates
# ExtendedCertificatesAndCertificates ::=
#   SET OF ExtendedCertificateOrCertificate

class ExtendedCertificatesAndCertificates:

    @classmethod
    def parse(cls, decoder=None, data=None, expect=None):
        decoder = get_decoder(decoder, data)
        if not expect:
            expect = universal_set
        logger.debug("Expect = %s" % str(expect))
        tag = decoder.peek()
        if tag != expect:
            raise ASN1Error({'expected': expect, 'found': tag})
        return SetOf(ExtendedCertificateOrCertificate, decoder, data, expect=expect)

# ExtendedCertificateOrCertificate ::= CHOICE {
#   certificate Certificate, -- X.509
#   extendedCertificate [0] IMPLICIT ExtendedCertificate }

class ExtendedCertificateOrCertificate:

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)
        logger.debug("ExtendedCertificateOrCertificate: %d bytes pending" % decoder.current_length())

        tag = decoder.peek()
        logger.debug("Found tag %s" % str(tag))
        if tag == context_any0:
            # TBC: Unclear, unused in our examples
            cert = ExtendedCertificate.parse()
            obj.extendedCertificate = cert
        else:
            # We can't use decoder.read(), we need the raw data
            # It is a hack, maybe hard to maintain, Maybe propose
            # upstream
            tag, val = decoder.read_raw()
            logger.debug("Cert. len=%d, val=%s" % (len(val), hexlify(val)))
            cert = x509.load_der_x509_certificate(val)
            logger.debug(cert.subject)
            obj.certificate = cert
        return cert

# SignerInfos ::= SET OF SignerInfo

class SignerInfos:

    @classmethod
    def parse(cls, decoder=None, data=None):
        return SetOf(SignerInfo, decoder, data)

# 6.7 IssuerAndSerialNumber
# IssuerAndSerialNumber ::= SEQUENCE {
#   issuer Name,
#   serialNumber CertificateSerialNumber }
class IssuerAndSerialNumber:

    def __str__(self):
        return ("%s (%x)" % (
            self.issuer.name.rfc4514_string(),
            self.serialNumber))

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)

        tag = decoder.peek()
        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})

        decoder.enter()
        obj.issuer = Name.parse(decoder)
        tag, val = decoder.read()
        if tag != universal_integer:
            raise ASN1Error({'expected': universal_integer, 'found': tag})
        obj.serialNumber = val
        decoder.leave()

        return obj

    @classmethod
    def build(cls, certificate):
        obj = cls()
        obj.issuer = certificate.issuer
        obj.serialNumber = certificate.serial_number

        return obj

    def asn1_serialize(self, encoder):
        encoder.enter(asn1.Numbers.Sequence)
        # Problema. Self.issuer es un x509Name, no podemos usar:
        # self.issuer.asn1_serialize(encoder)

        issuer_der_bytes = self.issuer.public_bytes()
        encoder.write(peel(issuer_der_bytes)[1], asn1.Numbers.Sequence, asn1.Types.Constructed)
       
        encoder.write(self.serialNumber)
        encoder.leave()

# 7. General syntax
# ContentInfo ::= SEQUENCE {
#   contentType ContentType,
#   content
#   [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
#
# ContentType ::= OBJECT IDENTIFIER

class ContentInfo:

    def __init__(self, contentType=None, content=None):
        self.contentType = contentType
        self.content = content

    def __str__(self):
        if self.contentType.dotted_string == SignedData_OID:
            pass
        return "ContentInfo: %s" % self.contentType.dotted_string
    
    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)

        logger.info("ContentInfo: %d bytes pending" % decoder.current_length())

        tag = decoder.peek()
        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})

        decoder.enter()

        tag, val = decoder.read()
        if tag != universal_oid:
            raise ASN1Error({'expected': universal_oid, 'found': tag})

        oid = val
        logger.info("ContentType: %s" % oid2name(oid))
        obj.contentType = x509.ObjectIdentifier(oid)

        # elif tag == universal_sequence:
        tag = decoder.peek()
        if tag != context_any0:
            raise ASN1Error({'expected': context_any0, 'found': tag})

        decoder.enter()
        if oid == Data_OID:
            tag, val = decoder.read()
            if tag != normal_octetstring:
                raise ASN1Error({'expected': normal_octetstring, 'found': tag})
            obj.content = val
            
        elif oid == SignedData_OID:
            obj.content = SignedData.parse(decoder)

        elif oid == SPC_INDIRECT_DATA_OBJID:
            
            # Apparently Microsoft uses the same OID for both
            # May be SpcIndirectDataContent or SpcIndirectDataContentV2
            # But we don't know which
            # We need to peek into the data.type value

            # spcIndirectDataContent = SpcIndirectDataContent.parse(decoder)

            # type_oid = spcIndirectDataContent.data.value.dotted_string
            # if type_od == '1.3.6.1.4.1.311.2.1.29':
            #     spcIndirectDataContent
            # elif type_oid == '1.3.6.1.4.1.311.2.1.31':
            #     SigFormatDescriptorV1
            # else:
            #    raise ValueError

            obj.content = SpcIndirectDataContent.parse(decoder)
            
        else:
            raise ValueError("Content %s is unsupported" % oid)
        decoder.leave()

        decoder.leave()

        return obj

    # ContentInfo
    @classmethod
    def build(cls,
              content_type=x509.ObjectIdentifier(Data_OID),
              content=None,
              filepath=None):
        obj = cls()
        obj.contentType = content_type
        if content_type == x509.ObjectIdentifier(Data_OID) and not content and filepath:
            obj.content = open(filepath, 'rb').read()
        else:
            obj.content = content

        return obj

    # TBC: lo de funcionar o no, mejor con una función superior que
    # que encapsule cualquier función. Todas estas clases las haríamos hijas
    # de la superclase en la que definiríamos el recubirmiento. O así.
    def asn1_serialize(self, encoder):
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(self.contentType.dotted_string, asn1.Numbers.ObjectIdentifier)
        encoder.enter(0, asn1.Classes.Context)

        logger.debug("contentType is {}".format(self.contentType))
        logger.debug("content is {}".format(hexlify(self.content)))
        # We did this for files, where the info should be coded
        # as OctetString, but it may be any ASN.1 structure
        # self.content is bytes, but should not be coded as an Octet Strincg
        # We meed to output it raw
        decoder = asn1.Decoder()
        decoder.start(self.content)
        tag, value = decoder.read()
        encoder.write(value=value, nr=tag.nr, typ=tag.typ, cls=tag.cls)
        encoder.leave()
        encoder.leave()
        return
    
# 9.1 SignedData type
# SignedData ::= SEQUENCE {
#      version Version,
#      digestAlgorithms DigestAlgorithmIdentifiers,
#      contentInfo ContentInfo,
#      certificates
#         [0] IMPLICIT ExtendedCertificatesAndCertificates
#           OPTIONAL,
#      crls
#        [1] IMPLICIT CertificateRevocationLists OPTIONAL,
#     signerInfos SignerInfos }

# DigestAlgorithmIdentifiers ::=
#   SET OF DigestAlgorithmIdentifier
#
# SignerInfos ::= SET OF SignerInfo

class SignedData:

    def __str__(self):
        return "SignedData: (%d) (%s) certificates: %s " % (
            self.version,
            self.contentInfo,
            '; '.join(x.subject.rfc4514_string() for x in self.certificates),
        )

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)

        logger.info("SignedData: %d bytes pending" % decoder.current_length())

        tag = decoder.peek()
        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})

        decoder.enter()

        tag, val = decoder.read()
        if tag != universal_integer:
            raise ASN1Error({'expected': universal_integer, 'found': tag})
        obj.version = val

        tag = decoder.peek()
        if tag != universal_set:
            raise ASN1Error({'expected': universal_set, 'found': tag})

        obj.digestAlgorithms = SetOf(DigestAlgorithmIdentifier, decoder, data)

        tag = decoder.peek()
        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})

        obj.contentInfo = ContentInfo.parse(decoder)

        tag = decoder.peek()
        if tag == context_any0:
            obj.certificates = ExtendedCertificatesAndCertificates.parse(decoder, expect=tag)
        else:
            obj.certificates = None

        tag = decoder.peek()
        if tag == context_any1:
            obj.crls = CertificateRevocationLists.parse(decoder, expect=tag)
        else:
            obj.crls = None

        obj.signerInfos = SignerInfos.parse(decoder)

        decoder.leave()

        return obj

    @classmethod
    def build(cls,
              content_info=None,
              authenticated_attributes=None,
              signer_infos=[],
              certificates=[]):

        obj = cls()

        obj.version = 1
        obj.digestAlgorithms = set()
        obj.contentInfo = content_info
        obj.authenticated_attributes = authenticated_attributes
        obj.certificates = certificates
        obj.signerInfos = signer_infos

        for signerInfo in obj.signerInfos:
            if signerInfo.digestAlgorithm not in obj.digestAlgorithms:
                obj.digestAlgorithms.add(signerInfo.digestAlgorithm)
        
        return obj
       
    def asn1_serialize(self, encoder):
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(1)	# version
        encoder.enter(asn1.Numbers.Set)
        for algorithm in self.digestAlgorithms:
            algorithm.asn1_serialize(encoder)
        encoder.leave()
        self.contentInfo.asn1_serialize(encoder)
        if self.certificates and len(self.certificates):
            # We could do this like the rest.
            encoder.enter(0, asn1.Classes.Context)
            for certificate in self.certificates:
                v = peel(certificate.public_bytes(serialization.Encoding.DER))[1]
                logger.debug(type(v))
                encoder.write(v, asn1.Numbers.Sequence, asn1.Types.Constructed)
            encoder.leave()

        else:
            logger.error("No certificates")

        encoder.enter(asn1.Numbers.Set)
        for signer_info in self.signerInfos:
            signer_info.asn1_serialize(encoder)
        encoder.leave()
        
        encoder.leave()
        return
    
# 9.2 SignerInfo type
# SignerInfo ::= SEQUENCE {
#   version Version,
#   issuerAndSerialNumber IssuerAndSerialNumber,
#   digestAlgorithm DigestAlgorithmIdentifier,
#   authenticatedAttributes
#     [0] IMPLICIT Attributes OPTIONAL,
#   digestEncryptionAlgorithm
#     DigestEncryptionAlgorithmIdentifier,
#   encryptedDigest EncryptedDigest,
#   unauthenticatedAttributes
#     [1] IMPLICIT Attributes OPTIONAL }

# EncryptedDigest ::= OCTET STRING

class SignerInfo:

    def __str__(self):
        return ("SignerInfo: %s by %s with %s" % (
            hexlify(self.encryptedDigest),
            self.issuerAndSerialNumber,
            self.digestEncryptionAlgorithm))

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)

        tag = decoder.peek()

        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})

        decoder.enter()
        tag, val = decoder.read()
        if tag != universal_integer:
            raise ASN1Error({'expected': universal_integer, 'found': tag})
        obj.version = val
        obj.issuerAndSerialNumber = IssuerAndSerialNumber.parse(decoder)
        obj.digestAlgorithm = DigestAlgorithmIdentifier.parse(decoder)
        tag = decoder.peek()
        if tag == context_any0:
            obj.authenticatedAttributes = Attributes.parse(decoder)
        else:
            obj.authenticatedAttributes = None
        obj.digestEncryptionAlgorithm = DigestEncryptionAlgorithmIdentifier.parse(decoder)
        tag, val = decoder.read()
        if tag != normal_octetstring:
            raise ASN1Error({'expected': normal_octetstring, 'found': tag})
        obj.encryptedDigest = val
        if tag == context_any1:
            obj.unauthenticatedAttributes = Attributes.parse(decoder)
        else:
            obj.unauthenticatedAttributes = None

        decoder.leave()

        return obj

    @classmethod
    def build(cls, 
              certificate,
              digestAlgorithm,
              digestEncryptionAlgorithm,
              signer_engine,
              content_info,
              authenticatedAttributes=None,
              unauthenticatedAttributes=None):
    
        obj = cls()
        obj.version = 1
        obj.certificate = certificate
        obj.issuerAndSerialNumber = IssuerAndSerialNumber.build(certificate)
        obj.digestAlgorithm = digestAlgorithm
        obj.digestEncryptionAlgorithm = digestEncryptionAlgorithm
        obj.contentInfo = content_info
        obj.signer_engine = signer_engine
        obj.encryptedDigest = None 
        obj.authenticatedAttributes = authenticatedAttributes
        obj.unauthenticatedAttributes = unauthenticatedAttributes

        logger.debug(obj.contentInfo.contentType)
        logger.debug(obj.contentInfo.content)
        # First compute the value we need to sign
        # !!!Wait, this is wrong!!! we need the full signature
        # logger.error(self.digest)
        if obj.authenticatedAttributes:
            saa_encoder = asn1.Encoder()
            saa_encoder.start()
            # Attention here!!!
            # See RRC 2315 9.3 Message-digesting process
            # Even if authenticatedAttributes is defined as
            # [0] IMPLICIT Attributes OPTIONAL
            # section 9.3 mandates that it is hashed as what an Attributes
            # type is, i.e. a SET. When the authenticated attributes are
            # included in a SignerInfo, it needs to be tagged as [0]
            # instead of SET. asn1_serialize knows the difference because
            # here we will not set a value for the tag argument, so it will
            # be serialized as a SET.
            obj.authenticatedAttributes.asn1_serialize(saa_encoder)
            serialized_authenticated_attributes = saa_encoder.output()
            logger.error("SAA: {}".format(hexlify(serialized_authenticated_attributes)))
            aa_encoder = asn1.Encoder()
            aa_encoder.start()
            obj.authenticatedAttributes.asn1_serialize(aa_encoder, tag=0)
            aa = aa_encoder.output()
            logger.error("AA: {}".format(hexlify(aa)))
            obj.digest = obj.digestAlgorithm.compute(serialized_authenticated_attributes).digest()
        else:
            obj.digest = obj.digestAlgorithm.compute(obj.contentInfo.content).digest()

        return obj

    def asn1_serialize(self, encoder):
        encryptedDigest = self.signer_engine.sign(self.digest)
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(self.version)
        self.issuerAndSerialNumber.asn1_serialize(encoder)
        self.digestAlgorithm.asn1_serialize(encoder)
        # Here we instruct asn1_serialize to encode it as a
        # [0] instead of a SET
        self.authenticatedAttributes.asn1_serialize(encoder, tag=0)
        self.digestEncryptionAlgorithm.asn1_serialize(encoder)
        encoder.write(encryptedDigest, asn1.Numbers.OctetString)
        # TBC: unauthenticatedAtributes
        
        encoder.leave()
        
# 9.4 Digest-encryption process
# DigestInfo ::= SEQUENCE {
#   digestAlgorithm DigestAlgorithmIdentifier,
#   digest Digest }
#
# Digest ::= OCTET STRING
# Often a DER encoding of another structure

class DigestInfo:

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)
        logger.debug("DigestInfo: %d bytes pending" % decoder.current_length())

        tag = decoder.peek()
        if tag != universal_sequence:
            raise ASN1Error({'expected': universal_sequence, 'found': tag})

        decoder.enter()
        obj.digestAlgorithm = AlgorithmIdentifier.parse(decoder)
        obj.digest = get_universal_octetstring(decoder)
        logger.debug("DigestInfo digest: %s" % hexlify(obj.digest))
        decoder.leave()

        return obj

    def zoom_in(self, cls):
        logger.debug(cls)
        logger.debug(hexlify(self.digest))
        digest_parsed = cls.parse(data=self.digest)
        logger.debug(digest_parsed)
        self.digest_parsed = digest_parsed

    def asn1_serialize(self, encoder):
        encoder.enter(asn1.Numbers.Sequence)
        encoder.leave()
            
class SignedDataBuilder:
    def __init__(self):
        self._content_info = None
        self._signers = []
        self._certificates = []
        self._extra_certificates = []
        self._crls = []
        self._digestAlgorithms = set()
        self._default_digest_algorithm = DigestAlgorithmIdentifier.build('SHA256')
        self._authenticated_attributes = set()
        self._digest_encryption_algorithm = AlgorithmIdentifier.build('rsaEncryption')
        self._unauthenticated_attributes = set()

        self._signer_engine = None
       
    def default_rsa_sign(self, private_key_file, password):
        private_key = load_private_key(private_key_file, password)
        
        return 

    def add_contentInfo(self, contentInfo):
        '''Add content already prepared'''
        self._content_info = contentInfo
        return self

    def add_content(self, contentType, content):
        '''Add content already prepared'''
        logger.debug("contentType is {}".format(contentType))
        logger.debug("content is {}".format(hexlify(content)))
        if contentType.dotted_string != Data_OID:
            # TBC: Check that these requirements are met
            if False:
                raise ValueError("If the contentType is not data, a signedContentType is needed, see RFC2315 #9.1")
            if False:
                raise ValueError("If the contentType is not data, a messageDigest is needed, see RFC2315 #9.1")
        self._content_info = ContentInfo(
            contentType=contentType,
            content=content)
        return self

    def add_content_file(self, filepath):
        self._input_file_path = filepath
        self._content_info = ContentInfo.build(filepath=filepath)
        logger.debug(self._content_info.contentType)
        logger.debug(self._content_info.content)
        return self
    
    def add_signer(self, signer):
        if not signer in self._signers:
            self._signers.append(signer)
        return self

    def add_digest_algorithm(self, algorithm):
        digestAlgorithm = DigestAlgorithmIdentifier.build(oid=algorithm)
        self._digestAlgorithms.add(digestAlgorithm)

    def add_certificate(self, certificate_path):
        cert = load_certificate(certificate_path)
        if not cert in self._extra_certificates:
            self._extra_certificates,append(cert)

    def add_authenticated_attribute(self, oid, values):
        if not self._authenticated_attributes:
            self._authenticated_attributes = Attributes()
        self._authenticated_attributes.add_attribute(Attribute.build(oid, values))

    def set_signer_engine(self, signer_engine):
        self._signer_engine = signer_engine
        
    def output(self, format='PEM'):
        '''Return a serialized ContentInfo containing a SignedData'''

        if format not in ('PEM', 'DER'):
            raise ValueError("Invalid format {}".format(format))

        signerInfos = set()
        for signer in self._signers:
            certificate = signer
            if not certificate in self._certificates:
                self._certificates.append(certificate)
            if len (self._digestAlgorithms) > 0:
                digestAlgorithm = list(self._digestAlgorithms)[0]
            else:
                digestAlgorithm = self._default_digest_algorithm
            authenticatedAttributes = self._authenticated_attributes
            digestEncryptionAlgorithm = self._digest_encryption_algorithm
            unauthenticatedAttributes = self._unauthenticated_attributes
            signer_engine = self._signer_engine
            signerInfo = SignerInfo.build(
                certificate,
                digestAlgorithm=digestAlgorithm,
                digestEncryptionAlgorithm=digestEncryptionAlgorithm,
                signer_engine=signer_engine,
                content_info=self._content_info,
                authenticatedAttributes=authenticatedAttributes,
                unauthenticatedAttributes=unauthenticatedAttributes)
            signerInfos.add(signerInfo)
                
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(SignedData_OID, asn1.Numbers.ObjectIdentifier)
        encoder.enter(0, asn1.Classes.Context)
        print(self._certificates)
        print(self._extra_certificates)
        signed_data = SignedData.build(
            content_info=self._content_info,
            authenticated_attributes=self._authenticated_attributes,
            signer_infos=signerInfos,
            certificates=self._certificates + self._extra_certificates)
        signed_data.asn1_serialize(encoder)
        encoder.leave()
        encoder.leave()
        result = encoder.output()
        if format == 'DER':
            return result
        elif format == 'PEM':
            return b'-----BEGIN PKCS7-----\n' + base64.encodebytes(result) + b'-----END PKCS7-----\n'
        else:
            raise ValueError

def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog='py-pkcs7',
        description='Read and write some kinds of PKCS #7 files',
        epilog='TBC')

    parser.add_argument('command', choices=('sign', 'verify'))
    parser.add_argument('-f', '--filename', type=str)
    parser.add_argument('-s', '--signer-certificate', type=str)
    parser.add_argument('-k', '--private-key', type=str)
    parser.add_argument('-c', '--certificate', type=str)
    
    args = parser.parse_args()
    if args.command == 'sign':
        builder = SignedDataBuilder()
        builder.add_content_file(
            args.filename
        )
        builder.add_signer(
            args.signer_certificate
        )
        # TBC: get more than one
        if args.certificate:
            builder.add_certificate(args.certificate)

        if args.private_key:
            builder.add_private_key(args.private_key)

        print(builder.output().decode('ascii'))

if __name__ == '__main__':
    # help(Name)
    # sys.exit(1)
    main()
