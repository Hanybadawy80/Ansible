""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import re, compoundfiles, urllib.parse, email.message, email.parser, email.policy
from functools import reduce
from connectors.core.connector import get_logger, ConnectorError
from email.utils import formatdate, formataddr
from .exchange_const import property_tags

logger = get_logger('exchange')


def load(filename_or_stream):
    try:
        with compoundfiles.CompoundFileReader(filename_or_stream) as doc:
            doc.rtf_attachments = 0
            return load_message_stream(doc.root, True, doc)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def load_message_stream(entry, is_top_level, doc):
    try:
        # Load stream data.
        props = parse_properties(entry['__properties_version1.0'], is_top_level, entry, doc)

        # Construct the MIME message....
        msg = email.message.EmailMessage()

        # Add the raw headers, if known.
        if 'TRANSPORT_MESSAGE_HEADERS' in props:
            # Get the string holding all of the headers.
            headers = props['TRANSPORT_MESSAGE_HEADERS']
            if isinstance(headers, bytes):
                headers = headers.decode("utf-8")

            headers = re.sub("Content-Type: .*(\n\s.*)*\n", "", headers, re.I)

            # Parse them.
            headers = email.parser.HeaderParser(policy=email.policy.default).parsestr(headers)

            # Copy them into the message object.
            for header, value in headers.items():
                msg[header] = value

        else:
            # Construct common headers from metadata.

            msg['Date'] = formatdate(props['MESSAGE_DELIVERY_TIME'].timestamp())
            del props['MESSAGE_DELIVERY_TIME']

            if props['SENDER_NAME'] != props['SENT_REPRESENTING_NAME']:
                props['SENDER_NAME'] += " (" + props['SENT_REPRESENTING_NAME'] + ")"
            del props['SENT_REPRESENTING_NAME']
            msg['From'] = formataddr((props['SENDER_NAME'], ""))
            del props['SENDER_NAME']

            msg['To'] = props['DISPLAY_TO']
            del props['DISPLAY_TO']

            msg['CC'] = props['DISPLAY_CC']
            del props['DISPLAY_CC']

            msg['BCC'] = props['DISPLAY_BCC']
            del props['DISPLAY_BCC']

            msg['Subject'] = props['SUBJECT']
            del props['SUBJECT']

        # Add the plain-text body from the BODY field.
        if 'BODY' in props:
            body = props['BODY']
            if isinstance(body, str):
                msg.set_content(body, cte='quoted-printable')
            else:
                msg.set_content(body, maintype="text", subtype="plain", cte='8bit')

        # Plain-text is not availabe. Use the rich text version.
        else:
            doc.rtf_attachments += 1
            fn = "messagebody_{}.rtf".format(doc.rtf_attachments)

            msg.set_content("<no plain text message body --- see attachment {}>".format(fn), cte='quoted-printable')

            # Decompress the value to Rich Text Format.
            import compressed_rtf
            rtf = props['RTF_COMPRESSED']
            rtf = compressed_rtf.decompress(rtf)

            # Add RTF file as an attachment.
            msg.add_attachment(rtf, maintype="text", subtype="rtf", filename=fn)

        # Add attachments.
        for stream in entry:
            if stream.name.startswith("__attach_version1.0_#"):
                process_attachment(msg, stream, doc)

        return msg
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def process_attachment(msg, entry, doc):
    try:
        # Load attachment stream.
        props = parse_properties(entry['__properties_version1.0'], False, entry, doc)

        # The attachment content...
        blob = props['ATTACH_DATA_BIN']

        # Get the filename and MIME type of the attachment.
        filename = props.get('ATTACH_LONG_FILENAME') or props.get("ATTACH_FILENAME") or props.get("DISPLAY_NAME")
        if isinstance(filename, bytes): filename = filename.decode("utf8")

        mime_type = props.get('ATTACH_MIME_TAG', 'application/octet-stream')
        if isinstance(mime_type, bytes): mime_type = mime_type.decode("utf8")

        # Python 3.6.
        if isinstance(blob, str):
            msg.add_attachment(blob, filename=filename)
        elif isinstance(blob, bytes):
            msg.add_attachment(blob, maintype=mime_type.split("/", 1)[0], subtype=mime_type.split("/", 1)[-1],
                               filename=filename)
        else:  # a Message instance
            msg.add_attachment(blob, filename=filename)
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def parse_properties(properties, is_top_level, container, doc):
    # Read a properties stream and return a Python dictionary
    # of the fields and values, using human-readable field names
    # in the mapping at the top of this module.
    try:
        # Load stream content.
        with doc.open(properties) as stream:
            stream = stream.read()

        # Skip header.
        i = (32 if is_top_level else 24)

        # Read 16-byte entries.
        ret = {}
        while i < len(stream):
            # Read the entry.
            property_type = stream[i + 0:i + 2]
            property_tag = stream[i + 2:i + 4]
            flags = stream[i + 4:i + 8]
            value = stream[i + 8:i + 16]
            i += 16

            # Turn the byte strings into numbers and look up the property type.
            property_type = property_type[0] + (property_type[1] << 8)
            property_tag = property_tag[0] + (property_tag[1] << 8)
            if property_tag not in property_tags: continue  # should not happen
            tag_name, _ = property_tags[property_tag]
            tag_type = property_types.get(property_type)

            # Fixed Length Properties.
            if isinstance(tag_type, FixedLengthValueLoader):
                value = tag_type.load(value)

            # Variable Length Properties.
            elif isinstance(tag_type, VariableLengthValueLoader):
                value_length = stream[i + 8:i + 12]  # not used

                streamname = "__substg1.0_{0:0{1}X}{2:0{3}X}".format(property_tag, 4, property_type, 4)
                try:
                    with doc.open(container[streamname]) as innerstream:
                        value = innerstream.read()
                except:
                    # Stream isn't present!
                    continue

                value = tag_type.load(value)

            elif isinstance(tag_type, EMBEDDED_MESSAGE):
                # Look up the stream in the document that holds the attachment.
                streamname = "__substg1.0_{0:0{1}X}{2:0{3}X}".format(property_tag, 4, property_type, 4)
                try:
                    value = container[streamname]
                except:
                    # Stream isn't present!
                    continue
                value = tag_type.load(value, doc)

            else:
                # unrecognized type
                continue

            ret[tag_name] = value

        return ret
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


# PROPERTY VALUE LOADERS

class FixedLengthValueLoader(object):
    pass


class NULL(FixedLengthValueLoader):
    @staticmethod
    def load(value):
        # value is an eight-byte long bytestring with unused content.
        return None


class BOOLEAN(FixedLengthValueLoader):
    @staticmethod
    def load(value):
        # value is an eight-byte long bytestring holding a two-byte integer.
        return value[0] == 1


class INTEGER16(FixedLengthValueLoader):
    @staticmethod
    def load(value):
        # value is an eight-byte long bytestring holding a two-byte integer.
        return reduce(lambda a, b: (a << 8) + b, reversed(value[0:2]))


class INTEGER32(FixedLengthValueLoader):
    @staticmethod
    def load(value):
        # value is an eight-byte long bytestring holding a four-byte integer.
        return reduce(lambda a, b: (a << 8) + b, reversed(value[0:4]))


class INTEGER64(FixedLengthValueLoader):
    @staticmethod
    def load(value):
        # value is an eight-byte long bytestring holding an eight-byte integer.
        return reduce(lambda a, b: (a << 8) + b, reversed(value))


class INTTIME(FixedLengthValueLoader):
    @staticmethod
    def load(value):
        # value is an eight-byte long bytestring encoding the integer number of
        # 100-nanosecond intervals since January 1, 1601.
        from datetime import datetime, timedelta
        value = reduce(lambda a, b: (a << 8) + b, reversed(value))  # bytestring to integer
        value = datetime(1601, 1, 1) + timedelta(seconds=value / 10000000)
        return value


# TODO: The other fixed-length data types:
# "FLOAT", "DOUBLE", "CURRENCY", "APPTIME", "ERROR"

class VariableLengthValueLoader(object):
    pass


class BINARY(VariableLengthValueLoader):
    @staticmethod
    def load(value):
        # value is a bytestring. Just return it.
        return value


class STRING8(VariableLengthValueLoader):
    @staticmethod
    def load(value):
        # value is a bytestring. I haven't seen specified what character encoding
        # is used when the Unicode storage type is not used, so we'll assume it's
        # ASCII or Latin-1 like but we'll use UTF-8 to cover the bases.
        try:
            return value.decode("utf8")
        except Exception as e:
            return value


class UNICODE(VariableLengthValueLoader):
    @staticmethod
    def load(value):
        # value is a bytestring. I haven't seen specified what character encoding
        # is used when the Unicode storage type is not used, so we'll assume it's
        # ASCII or Latin-1 like but we'll use UTF-8 to cover the bases.
        return value.decode("utf16")


# TODO: The other variable-length tag types are "CLSID", "OBJECT".

class EMBEDDED_MESSAGE(object):
    @staticmethod
    def load(entry, doc):
        return load_message_stream(entry, False, doc)


# CONSTANTS

property_types = {
    0x1: NULL(),
    0x2: INTEGER16(),
    0x3: INTEGER32(),
    0x4: "FLOAT",
    0x5: "DOUBLE",
    0x6: "CURRENCY",
    0x7: "APPTIME",
    0xa: "ERROR",
    0xb: BOOLEAN(),
    0xd: EMBEDDED_MESSAGE(),
    0x14: INTEGER64(),
    0x1e: STRING8(),
    0x1f: UNICODE(),
    0x40: INTTIME(),
    0x48: "CLSID",
    0xFB: "SVREID",
    0xFD: "SRESTRICT",
    0xFE: "ACTIONS",
    0x102: BINARY(),
}

