
# Handle pkcs7 data in ways that pyca cannot right now
# As much as possible, support form pyca has been used

import asn1
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from binascii import hexlify
from struct import unpack

import logging
logger = logging.getLogger(__name__)

cryptography_backend = default_backend()

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

class DigestAlgorithmIdentifier(AlgorithmIdentifier):
    pass

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

class Attributes:

    @classmethod
    def parse(cls, decoder=None, data=None):
        obj = cls()
        decoder = get_decoder(decoder, data)
        logger.debug("Attributes: %s pending (%s)" % (decoder.current_length(), hexlify(decoder.current_buffer()[:32])))

        obj.attributes = set()

        decoder.enter()
        tag = decoder.peek()
        while tag:
            obj.attributes.add(Attribute.parse(decoder))
            tag = decoder.peek()
        decoder.leave()

        return obj

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
            cert = x509.load_der_x509_certificate(val, backend=cryptography_backend)
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

# 7. General syntax
# ContentInfo ::= SEQUENCE {
#   contentType ContentType,
#   content
#   [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
#
# ContentType ::= OBJECT IDENTIFIER

class ContentInfo:

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
