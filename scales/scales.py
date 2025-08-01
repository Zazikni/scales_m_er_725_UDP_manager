import socket
import time
from typing import Optional
import logging
from .utilities import get_json_from_bytearray


class Scales:
    def __init__(self, ip, port, password):

        self.ip: str = ip
        self.port: int = port
        self.__password: str = password
        self.__STX = bytes([0x02])
        self.__get_socket()

    def __del__(self):
        self.__socket.close()

    def __get_socket(self):
        try:
            self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except Exception as e:
            logging.error(f"Не удалось создать сокет\n{e}")
            raise e

    def __file_creation_request_gen(self) -> bytes:
        command = bytes([0xFF, 0x14])
        payload = command + self.__password.encode("ASCII")
        return self.__STX + bytes([len(payload)]) + payload

    def __file_creation_status_request_gen(self) -> bytes:
        command = bytes([0xFF, 0x15])
        payload = command + self.__password.encode("ASCII")
        return self.__STX + bytes([len(payload)]) + payload

    def __hash_calculating_request_gen(self) -> bytes:
        command = bytes([0xFF, 0x12])
        hash_calc_code = 0x06
        payload = command + self.__password.encode("ASCII") + bytes([hash_calc_code])
        return self.__STX + bytes([len(payload)]) + payload

    def __hash_calculating_status_request_gen(self) -> bytes:
        command = bytes([0xFF, 0x12])
        hash_calc_code = 0x07
        payload = command + self.__password.encode("ASCII") + bytes([hash_calc_code])
        return self.__STX + bytes([len(payload)]) + payload

    def __file_transfer_init_request_gen(self) -> bytes:
        command = bytes([0xFF, 0x12])
        hash_calc_code = 0x03
        payload = command + self.__password.encode("ASCII") + bytes([hash_calc_code])
        return self.__STX + bytes([len(payload)]) + payload

    def __send(self, data: bytes, label: str):
        logging.debug(f"[>] {label} | {len(data)} байт | HEX: {data.hex()} | {data}")
        self.__socket.sendto(data, (self.ip, self.port))

    def __recv_big_data(self, timeout: float = 20) -> Optional[tuple[bytes, tuple]]:
        self.__socket.settimeout(timeout)
        try:
            data, addr = self.__socket.recvfrom(65507)
            logging.debug(
                f"[<] От весов {addr} → {self.__socket.getsockname()[1]} | {len(data)} байт | {list(data[:13])}"
            )
            return data, addr
        except socket.timeout:
            return None

    def __recv(self, timeout: float = 5) -> Optional[tuple[bytes, tuple]]:
        self.__socket.settimeout(timeout)
        try:
            data, addr = self.__socket.recvfrom(2048)
            logging.debug(
                f"[<] От весов {addr} → {self.__socket.getsockname()[1]} | {len(data)} байт | HEX: {data.hex()} | {data} | {list(data)}"
            )
            return data, addr
        except socket.timeout:
            return None

    def get_products_json(self) -> dict:
        self.__send(
            self.__file_creation_request_gen(),
            "Пакет с запросом на создание файла",
        )
        self.__recv()

        while True:
            self.__send(
                self.__file_creation_status_request_gen(),
                "Пакет с запросом на получение статуса создания файла",
            )
            time.sleep(1)
            data_from_scales = self.__recv()
            if data_from_scales[0][4] == 172:
                continue
            else:
                # print("Data is ready to collect")
                break
        self.__send(
            self.__hash_calculating_request_gen(),
            "Пакет с запросом на начало расчёта хэш-данных",
        )
        self.__recv()
        # Если код статуса расчёта = 0
        # TODO Сделать обработку случая когда статус рассчета != 0
        self.__send(
            self.__hash_calculating_status_request_gen(),
            "Пакет с запросом на получение статуса расчёта хэш-данных",
        )
        self.__recv()

        file_data = bytearray()
        while True:
            self.__send(
                self.__file_transfer_init_request_gen(),
                "Пакет с запросом на получение порции файла",
            )
            data, address = self.__recv_big_data()
            is_last_chunk = data[5] == 1  # 6-й байт флаг последней порции
            file_data.extend(data[12:])
            if is_last_chunk:
                break
        return get_json_from_bytearray(file_data)

    def get_all_commands(self) -> dict:
        res = dict()
        res["1"] = self.__file_creation_request_gen()
        res["2"] = self.__file_creation_status_request_gen()
        res["3"] = self.__hash_calculating_request_gen()
        res["4"] = self.__hash_calculating_status_request_gen()
        res["5"] = self.__file_transfer_init_request_gen()
        return res
