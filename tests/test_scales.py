import pytest
from scales import Scales
from settings import *


@pytest.fixture
def default_scales():
    return Scales(password=SCALE_PASSWORD, ip=SCALE_IP, port=SCALE_PORT)


def test_json_commands(default_scales, subtests):
    commands = default_scales.get_all_commands()
    examples = {
        "1": b"\x02\x06\xff\x141234",
        "2": b"\x02\x06\xff\x151234",
        "3": b"\x02\x07\xff\x121234\x06",
        "4": b"\x02\x07\xff\x121234\x07",
        "5": b"\x02\x07\xff\x121234\x03",
    }
    for i in commands.keys():
        with subtests.test(value=i):
            assert commands[i] == examples[i]
