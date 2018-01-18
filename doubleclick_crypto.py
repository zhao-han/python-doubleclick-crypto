# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
#
# Author: zhaohan@cotxnetworks.com

from __future__ import absolute_import, division, print_function

import os
import six
import time
import struct
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend


class InvalidKeyException(Exception):
    pass


class InvalidSignature(Exception):
    pass


class SignatureException(Exception):
    pass


class Keys(object):
    """
    Holds the keys used to configure DoubleClick cryptography.
    """
    def __init__(self, encryption_key, integrity_key):
        self._valid_key(encryption_key)
        self._valid_key(integrity_key)

        self._encryption_key = encryption_key
        self._integrity_key = integrity_key

    def _valid_key(self, key):
        if not key:
            raise InvalidKeyException('Invalid key.')

        if not isinstance(key, six.binary_type):
            raise InvalidKeyException('Key must {} type.'.format(six.binary_type))

    @property
    def encryption_key(self):
        return self._encryption_key

    @property
    def integrity_key(self):
        return self._integrity_key

    @property
    def hashcode(self):
        return hash(self._encryption_key) ^ hash(self._integrity_key)

    def __eq__(self, other):
        if self is other:
            return True
        elif not isinstance(other, Keys):
            return False

        return (self.encryption_key == other.encryption_key) and \
               (self.integrity_key == other.integrity_key)

    def __str__(self):
        return "encryptionKey:<{}> integrityKey:<{}>".format(
            self._encryption_key,
            self._integrity_key
        )


class DoubleClickCrypto(object):
    """
    Encryption and decryption support for the DoubleClick Ad Exchange RTB protocol.

    Encrypted payloads are wrapped by "packages" in the general format:

    initVector:16 || E(payload:?) || I(signature:4)

    where:
        initVector = timestamp:8 || serverId:8} (AdX convention)
        E(payload) = payload ^ hmac(encryptionKey, initVector)} per max-20-byte block
        I(signature) = hmac(integrityKey, payload || initVector)[0..3]
    """

    KEY_ALGORITHM = hashes.SHA1

    # Initialization vector offset and size in the crypto package.
    IV_START = 0
    IV_END = 16
    IV_SIZE = 16

    # Timestamp subfield offset and size in the initialization vector.
    IV_TIMESTAMP_START = 0
    IV_TIMESTAMP_END = 8
    IV_TIMESTAMP_SIZE = 8

    # ServerId subfield offset and size in the initialization vector.
    IV_SERVERID_START = 8
    IV_SERVERID_END = 16
    IV_SERVERID_SIZE = 8

    # Payload offset in the crypto package.
    PAYLOAD_START = IV_START + IV_SIZE

    # Integrity signature size.
    SIGNATURE_SIZE = 4
    SIGNATURE_RSTART = -4

    # Overhead (non-Payload data) total size.
    OVERHEAD_SIZE = IV_SIZE + SIGNATURE_SIZE

    COUNTER_PAGESIZE = 20
    COUNTER_SECTIONS = 3 * 256 + 1
    MICROS_PER_CURRENCY_UNIT = 1000000

    def __init__(self, keys, backend=None):
        self._keys = keys

        if backend:
            self._backend = backend
        else:
            self._backend = default_backend()

    def init_plain_data(self, payload_size, init_vector=None):
        """Init plain data buffer

        :param payload_size:
        :param init_vector:
        :return: (initVector || payload || zeros:4)
        """
        plain_data = bytearray(self.OVERHEAD_SIZE + payload_size)

        if not init_vector:
            plain_data[self.IV_START: self.IV_END] = self._create_init_vector()
        else:
            plain_data[self.IV_START: self.IV_END] = init_vector

        return plain_data

    @classmethod
    def decode(cls, enc_data):
        """
        Decodes data, from string to binary form.
        The default implementation performs websafe-base64 decoding (RFC 3548).
        :param enc_data:
        :return:
        """
        if not enc_data:
            return None
        return base64.urlsafe_b64decode(enc_data)

    @classmethod
    def encode(cls, data):
        """
        Encodes data, from binary form to string.
        The default implementation performs websafe-base64 encoding (RFC 3548).
        :param data:
        :return:
        """
        if not data:
            return None
        return base64.urlsafe_b64encode(data)

    def decrypt(self, cipher_data):
        """
        Decrypts data.

        :param cipher_data: {initVector || E(payload) || I(signature)}
        :return: {initVector || payload || I'(signature)}
        """
        if not isinstance(cipher_data, six.binary_type):
            raise TypeError('cipher_data must bytes or str type.')

        if len(cipher_data) < self.OVERHEAD_SIZE:
            raise TypeError('Invalid cipher_data length: {}, minimum size: {}'.format(self.OVERHEAD_SIZE))

        work_bytes = bytearray(cipher_data)

        self._xor_payload_to_hmac_pad(work_bytes)
        confirmation_signature = self._hmac_signature(work_bytes)
        integrity_signature = work_bytes[self.SIGNATURE_RSTART:]

        if confirmation_signature != integrity_signature:
            raise InvalidSignature('Fail to verify signature')

        return work_bytes

    def encrypt(self, plain_data):
        """
        Encrypts data.

        :param plain_data: {initVector || payload || zeros:4}
        :return: {initVector || E(payload) || I(signature)}
        """
        if not isinstance(plain_data, bytearray):
            raise TypeError('plain_data must bytearray type.')

        if len(plain_data) < self.OVERHEAD_SIZE:
            raise TypeError('Invalid plain_data length: {}, minimum size: {}'.format(self.OVERHEAD_SIZE))

        work_bytes = bytearray(plain_data)

        signature = self._hmac_signature(work_bytes)
        work_bytes[self.SIGNATURE_RSTART:] = signature
        self._xor_payload_to_hmac_pad(work_bytes)

        return work_bytes

    @staticmethod
    def _timestamp_millis():
        t = time.time()
        return long(round(t * 1000))

    @staticmethod
    def _millis_to_secs_and_micros(millis):
        return ((millis // 1000) << 32) | ((millis % 1000) * 1000)

    @staticmethod
    def _secs_and_micros_to_millis(secs_micros):
        return ((secs_micros >> 32) * 1000) + (secs_micros & 0xFFFFFFFFL) / 1000

    def _create_init_vector(self):
        ts_millis = self._millis_to_secs_and_micros(self._timestamp_millis())
        server_id = os.urandom(self.IV_SERVERID_SIZE)

        # we use big-endian. Maybe google use little-endian. So let's try...
        init_vector = struct.pack(">Q", ts_millis) + server_id
        return init_vector

    def _get_timestamp(self, data):
        timestamp = struct.pack(">Q", data[self.IV_TIMESTAMP_START: self.IV_TIMESTAMP_END])
        return timestamp

    def _get_server_id(self, data):
        server_id = struct.pack(">Q", data[self.IV_SERVERID_START: self.IV_SERVERID_END])
        return server_id

    def _xor_payload_to_hmac_pad(self, work_bytes):
        """
        payload = payload ^ hmac(encryptionKey, initVector || counterBytes)
        """
        payload_size = len(work_bytes) - self.OVERHEAD_SIZE
        sections = (payload_size + self.COUNTER_PAGESIZE - 1) // self.COUNTER_PAGESIZE

        if sections > self.COUNTER_SECTIONS:
            raise OverflowError('Payload is {} bytes, exceeds limit of {}'.format(
                payload_size, self.COUNTER_PAGESIZE * self.COUNTER_SECTIONS
            ))

        iv = six.binary_type(work_bytes[self.IV_START: self.IV_END])
        pad = bytearray(self.COUNTER_PAGESIZE + 3)
        counter_size = 0

        for section in xrange(0, sections):
            section_base = section * self.COUNTER_PAGESIZE
            section_size = min(payload_size - section_base, self.COUNTER_PAGESIZE)
            h = HMAC(self._keys.encryption_key, self.KEY_ALGORITHM(), backend=self._backend)
            h.update(iv)

            if counter_size != 0:
                pad_page = six.binary_type(pad[self.COUNTER_PAGESIZE: (self.COUNTER_PAGESIZE + counter_size)])
                h.update(pad_page)

            pad[0:self.COUNTER_PAGESIZE] = h.finalize()

            for i in xrange(0, section_size):
                work_bytes[self.PAYLOAD_START + section_base + i] ^= pad[i]

            pad[0:self.COUNTER_PAGESIZE] = b'\x00' * self.COUNTER_PAGESIZE

            if counter_size == 0 or ++pad[self.COUNTER_PAGESIZE + counter_size - 1] == 0:
                counter_size += 1

    def _hmac_signature(self, work_bytes):
        try:
            iv = six.binary_type(work_bytes[self.IV_START: self.IV_SIZE])
            payload = six.binary_type(work_bytes[self.PAYLOAD_START: self.SIGNATURE_RSTART])

            h = HMAC(self._keys.integrity_key, self.KEY_ALGORITHM(), backend=self._backend)
            h.update(payload)
            h.update(iv)
            hmac = h.finalize()
            return hmac[0:4]
        except Exception:
            raise SignatureException


class Price(DoubleClickCrypto):
    """
    Encryption for winning price.

    <p>See <a href="https://developers.google.com/ad-exchange/rtb/response-guide/decrypt-price">
    Decrypting Price Confirmations</a>.
    """
    def __init__(self, keys, backend=None):
        super(Price, self).__init__(keys, backend)
        self.PAYLOAD_SIZE = 8
        self.PAYLOAD_END = self.PAYLOAD_START + self.PAYLOAD_SIZE

    def encrypt_price_micros(self, price_value, init_vector=None):
        """Encrypts the winning price.

        :param price_value: the price in micros (1/1.000.000th of the currency unit)
        :param init_vector: up to 16 bytes of nonce data
        :return: encrypted price
        """
        plain_data = self.init_plain_data(self.PAYLOAD_SIZE, init_vector)
        plain_data[self.PAYLOAD_START: self.PAYLOAD_END] = struct.pack(">Q", price_value)
        return self.encrypt(plain_data)

    def decrypt_price_micros(self, price_cipher):
        """Decrypts the winning price.

        :param price_cipher: priceCipher encrypted price
        :return: price value in micros (1/1.000.000th of the currency unit)
        """
        plain_data = self.decrypt(price_cipher)
        price_value, = struct.unpack(">Q", str(plain_data[self.PAYLOAD_START: self.PAYLOAD_END]))
        return price_value

    def encode_price_micros(self, price_micros, init_vector=None):
        """Encrypts and encodes the winning price.

        :param price_micros: the price in micros (1/1.000.000th of the currency unit)
        :param init_vector: up to 16 bytes of nonce data, or null for default generated data
        :return: encrypted price, encoded as websafe-base64
        """
        return self.encode(self.encrypt_price_micros(price_micros, init_vector))

    def encode_price_value(self, price_value, init_vector=None):
        """Encrypts and encodes the winning price.

        :param price_value: the price
        :param init_vector: up to 16 bytes of nonce data, or null for default generated data
        :return: encrypted price, encoded as websafe-base64
        """
        price_micros = long(price_value * self.MICROS_PER_CURRENCY_UNIT)
        return self.encode_price_micros(price_micros, init_vector)

    def decode_price_micros(self, price_cipher):
        """Decodes and decrypts the winning price.

        :param price_cipher: encrypted price, encoded as websafe-base64
        :return: price value in micros (1/1.000.000th of the currency unit)
        """
        return self.decrypt_price_micros(self.decode(price_cipher))

    def decode_price_value(self, price_cipher):
        """Decodes and decrypts the winning price.

        :param price_cipher: encrypted price, encoded as websafe-base64
        :return: price value
        """
        return self.decode_price_micros(price_cipher) / (float(self.MICROS_PER_CURRENCY_UNIT))



class AdId(DoubleClickCrypto):
    """
    Encryption for Advertising ID.

    <p>See
    <a href="https://developers.google.com/ad-exchange/rtb/response-guide/decrypt-advertising-id">
    Decrypting Advertising ID</a>.
    """
    def __init__(self, keys, backend=None):
        super(AdId, self).__init__(keys, backend)
        self.PAYLOAD_SIZE = 16
        self.PAYLOAD_END = self.PAYLOAD_START + self.PAYLOAD_SIZE

    def encrypt_adid(self, adid_plain, init_vector=None):
        if not isinstance(adid_plain, six.binary_type):
            raise TypeError('AdId should str or bytes type.')

        if len(adid_plain) != self.PAYLOAD_SIZE:
            raise TypeError('AdId is {} bytes, should be {}'.format(len(adid_plain), self.PAYLOAD_SIZE))

        plain_data = self.init_plain_data(self.PAYLOAD_SIZE, init_vector)
        plain_data[self.PAYLOAD_START: self.PAYLOAD_END] = adid_plain
        return six.binary_type(self.encrypt(plain_data))

    def decrypt_adid(self, adid_cipher):
        if not isinstance(adid_cipher, str):
            raise TypeError('AdId should str type.')

        if len(adid_cipher) != (self.PAYLOAD_SIZE + self.OVERHEAD_SIZE):
            raise TypeError('AdId is {} bytes, should be {}'.format(
                len(adid_cipher), (self.PAYLOAD_SIZE + self.OVERHEAD_SIZE)))

        plain_data = self.decrypt(adid_cipher)
        return six.binary_type(plain_data[self.PAYLOAD_START:self.PAYLOAD_END])


if __name__ == '__main__':

    encryption_key = b'cotxnetworks'
    integrity_key = b'0123456789'

    keys = Keys(encryption_key, integrity_key)
    assert(keys == keys)

    # test keys
    print('keys={}'.format(keys))
    print('keys.hashcode={}'.format(keys.hashcode))

    keys2 = Keys('abc', 'def')
    assert(keys != keys2)

    keys3 = Keys(encryption_key, integrity_key)
    assert(keys == keys3)

    # price encrypt/decrypt test
    price = Price(keys)

    price_value_ori = 1.55
    print('price_value_ori={}'.format(price_value_ori))

    price_cipher = price.encode_price_value(price_value=price_value_ori)
    print('price_cipher={}'.format(price_cipher))

    price_value = price.decode_price_value(price_cipher)
    print('price_value={}'.format(price_value))

    # adid encrypt/decrypt test
    import uuid
    adid = AdId(keys)

    adid_ori = uuid.UUID('12345678-1234-5678-1234-567812345678').bytes
    print('adid_ori={}'.format(adid_ori))

    adid_cipher = adid.encrypt_adid(adid_ori)
    print('adid_cipher={}'.format(adid_cipher))

    adid_plain = adid.decrypt_adid(adid_cipher)
    print('adid_plain={}'.format(adid_plain))