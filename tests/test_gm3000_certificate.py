"""Certificate framing regressions using synthetic data, without a USB token."""

import datetime
import unittest
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID, ObjectIdentifier

from bjca_service.longmai_gm3000 import GM3000Error, GM3000HID


def reports(payload):
    head = bytearray(65)
    head[1:4] = b"\xbf\xaa\xaa"
    head[4:6] = (len(payload) + 3).to_bytes(2, "little")
    head[25:25 + min(40, len(payload))] = payload[:40]
    result = [bytes(head)]
    rest = payload[40:]
    while rest:
        part, rest = rest[:63], rest[63:]
        frame = bytearray(65)
        frame[1] = 0x3F if rest else 0x40 | len(part)
        frame[2:2 + len(part)] = part
        result.append(bytes(frame))
    return result


def reader(cert, chunk_size=492, declared_length=None, final_status=b"\x90\x00"):
    frames = []
    for offset in range(0, len(cert), chunk_size):
        chunk = cert[offset:offset + chunk_size]
        if offset == 0:
            length = len(cert) if declared_length is None else declared_length
            chunk = b"\x00\x00" + length.to_bytes(2, "big") + chunk
        status = final_status if offset + chunk_size >= len(cert) else b"\x6a\x9e"
        frames.extend(reports(chunk + status))
    device = GM3000HID.__new__(GM3000HID)
    device._dev = Mock()
    device._seq = 0
    device.transceive = Mock(return_value=(b"", 0x9000))
    device._read_report = Mock(side_effect=frames)
    return device


class CertificateReadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = ed25519.Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic UKey")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(datetime.datetime(2026, 1, 1))
                .not_valid_after(datetime.datetime(2027, 1, 1))
                .add_extension(x509.UnrecognizedExtension(
                    ObjectIdentifier("1.2.3.4"), b"\x90\x00\x6a\x9e" * 225), False)
                .sign(key, None))
        cls.cert = cert.public_bytes(serialization.Encoding.DER)

    def test_complete_certificate_across_one_two_and_three_chunks(self):
        for chunk_size, count in ((2000, 1), (700, 2), (492, 3)):
            with self.subTest(chunks=count):
                device = reader(self.cert, chunk_size)
                self.assertEqual(device.export_certificate(), self.cert)
                self.assertEqual(device._dev.write.call_count, count)

    def test_declared_length_must_match(self):
        for delta in (-1, 110):
            with self.subTest(delta=delta):
                with self.assertRaises(GM3000Error):
                    reader(self.cert, declared_length=len(self.cert) + delta).export_certificate()

    def test_device_error_is_not_certificate_data(self):
        with self.assertRaisesRegex(GM3000Error, "0x6985"):
            reader(self.cert, final_status=b"\x69\x85").export_certificate()

    def test_invalid_der_is_rejected(self):
        with self.assertRaisesRegex(GM3000Error, "invalid DER"):
            reader(b"not a certificate").export_certificate()

    def test_truncated_continuation_is_rejected(self):
        device = reader(self.cert)
        frames = reports(b"\x00\x00" + len(self.cert).to_bytes(2, "big") + self.cert + b"\x90\x00")
        last = bytearray(frames[-1])
        last[1] -= 1
        device._read_report.side_effect = frames[:-1] + [bytes(last)]
        with self.assertRaisesRegex(GM3000Error, "incomplete cert response"):
            device.export_certificate()


if __name__ == "__main__":
    unittest.main()
