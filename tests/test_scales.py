import hashlib

import pytest
from scales import Scales


@pytest.fixture
def default_scales():
    return Scales(password="1234", ip="10.35.150.4", port=1111)


@pytest.fixture
def extra_long_password_scales():
    return Scales(password="1234" * 100, ip="10.35.150.4", port=1111)


def test_file_creation_request_gen(default_scales):
    assert (
        default_scales._Scales__file_creation_request_gen() == b"\x02\x06\xff\x141234"
    )


def test_file_creation_status_request_gen(default_scales):
    assert (
        default_scales._Scales__file_creation_status_request_gen()
        == b"\x02\x06\xff\x151234"
    )


def test_hash_calculating_request_gen(default_scales):
    assert (
        default_scales._Scales__hash_calculating_request_gen()
        == b"\x02\x07\xff\x121234\x06"
    )


def test_hash_calculating_status_request_gen(default_scales):
    assert (
        default_scales._Scales__hash_calculating_status_request_gen()
        == b"\x02\x07\xff\x121234\x07"
    )


def test_file_transfer_init_request_gen(default_scales):
    assert (
        default_scales._Scales__file_transfer_init_request_gen()
        == b"\x02\x07\xff\x121234\x03"
    )


def test_file_transfer_init_request_gen(default_scales, subtests):
    for i in range(1):
        with subtests.test(i):
            packet = default_scales._Scales__initial_file_transfer_request_gen(
                json_bytes, clear_database=i
            )
            print(packet)
            assert isinstance(packet, bytes)
            assert len(packet) == 36
            assert packet.startswith(Scales.Codes.Global.STX)  # STX
            payload = packet[2:]

            assert payload.startswith(
                Scales.Codes.JsonFileTransfer.FILE_TRANSFER_COMMAND_CODE
            )
            assert b"1234" == payload[2:6]
            expected_hash = hashlib.md5(json_bytes).digest()
            assert expected_hash == payload[7:23]
            assert b"\x04" == payload[23:24]
            assert len(json_bytes).to_bytes(8, byteorder="big") == payload[24:32]
            assert b"\x01" == payload[32:33]
            assert (b"\x00" if i == 1 else b"\x01") == payload[33:34]


json_bytes = b'{"categories":[{"idCategory":1,"name":"\xd0\xa4\xd1\x80\xd1\x83\xd0\xba\xd1\x82\xd1\x8b"}],"labelTemplates":[{"deleted":false,"height":30,"id":1,"name":"58x30, \xd0\xa8\xd0\x9a","width":58}],"messages":[{"deleted":false,"id":1,"value":"\xd0\xa1\xd1\x82\xd1\x80\xd0\xbe\xd0\xba\xd0\xb0 1\\n\xd0\xa1\xd1\x82\xd1\x80\xd0\xbe\xd0\xba\xd0\xb0 2\\n\\n\xd0\xa1\xd1\x82\xd1\x80\xd0\xbe\xd0\xba\xd0\xb0 4"}],"productRates":[{"productCode":2,"rate":1,"startDate":"02-02-23","updateDate":"02-02-23"}],"lotsOfProduct":[{"id":1,"productCode":1,"manufactureDate":"12-12-25","shelfLifeDateTime":"12-12-26 12-21"}],"products":[{"id":"1","code":"1","buttonNumber":"1","name":"\xd0\x9f\xd1\x80\xd0\xb8\xd0\xbc\xd0\xb5\xd1\x80\\n","price":"24.000000","shelfLifeInDays":"40","tare":"0.100000","productType":"PIECE","deleted":"false","pluNumber":"1","labelTemplate":"11","barcodeStructure":"[{\\"number\\":\\"1\\",\\"structure\\":\\"@{CODE:7}@{QUANTITY:5}@{CHECKSUM:<EAN_13>}\\",\\"type\\":8},{\\"number\\":\\"2\\",\\"structure\\":\\"@{TEXT:<ThisisaDataMatrix>}\\",\\"type\\":6}]","pieceWeight":"0.200000","manufactureDate":"21-12-23","barcodePrefixType":"NUMBER_SCALES","sellByDate":"09-02-24","minWeight":"0.015000","maxWeight":"0.215000","discountPrice":"20.500000","labelDiscountTemplate":"1","wrappingType":"5","gtin":"647"}]}'
