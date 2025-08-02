import hashlib
import json
import sys
import socket
import time
from typing import Optional, Tuple
import logging
from .utilities import get_json_from_bytearray


class Scales:
    def __init__(self, ip, port, password):

        self.ip: str = ip
        self.port: int = port
        self.__password: str = password
        self.__STX = bytes([0x02])
        self.__get_socket()
        self.__file_chunk_limit = 60000

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

    def __send_big_data(self, data: bytes, label: str):
        logging.debug(f"[>] {label} | {len(data)} байт | {list(data[:13])}")
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

    def __recv(
        self, timeout: float = 5, force_exit_if_timeout: bool = False
    ) -> Optional[tuple[bytes, tuple]]:
        self.__socket.settimeout(timeout)
        try:
            data, addr = self.__socket.recvfrom(2048)
            logging.debug(
                f"[<] От весов {addr} → {self.__socket.getsockname()[1]} | {len(data)} байт | HEX: {data.hex()} | {data} | {list(data)}"
            )
            return data, addr
        except socket.timeout:
            logging.warning("Не удалось получить ответ от весов за отведенное время.")
            if force_exit_if_timeout:
                sys.exit(1)
            else:
                return None

    def get_products_json(self) -> dict:
        self.__send(
            self.__file_creation_request_gen(),
            "Пакет с запросом на создание файла",
        )
        self.__recv(force_exit_if_timeout=True)

        while True:
            self.__send(
                self.__file_creation_status_request_gen(),
                "Пакет с запросом на получение статуса создания файла",
            )
            time.sleep(1)
            data_from_scales, address = self.__recv()
            if data_from_scales[4] == 172:
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

    def __initial_file_transfer_request_gen(
        self, data: bytes, clear_database: bool = False
    ) -> bytes:
        command = bytes([0xFF, 0x13])
        hash_sending_param = bytes([0x02])
        md5_hash = hashlib.md5(data).digest()
        file_size_param = bytes([0x04])
        file_export_type_param = bytes([0x01])
        file_export_type = bytes([0x00]) if clear_database else bytes([0x01])
        payload = (
            command
            + self.__password.encode("ASCII")
            + hash_sending_param
            + md5_hash
            + file_size_param
            + len(data).to_bytes(8, byteorder="big")
            + file_export_type_param
            + file_export_type
        )

        return self.__STX + bytes([len(payload)]) + payload

    def __file_transfer_commands_gen(
        self,
        data: bytes,
    ) -> Tuple[bytes, ...]:
        command = bytes([0xFF, 0x13])
        chunk_sending_param = bytes([0x03])
        offset_param = 0
        total_len = len(data)
        packets = []

        while offset_param < total_len:
            # текущая порция данных
            chunk = data[offset_param : offset_param + self.__file_chunk_limit]
            is_last = offset_param + self.__file_chunk_limit >= total_len

            is_last_byte = bytes([0x01]) if is_last else bytes([0x00])
            offset_bytes = offset_param.to_bytes(4, "little")
            chunk_len_bytes = len(chunk).to_bytes(2, "little")

            payload = (
                command
                + self.__password.encode("ascii")
                + chunk_sending_param
                + is_last_byte
                + offset_bytes
                + chunk_len_bytes
                + chunk
            )

            # заголовок в зависимости от длины
            if len(payload) <= 255:
                header = self.__STX + bytes([len(payload)])
            else:
                header = self.__STX + bytes([0xFF])

            packet = header + payload
            packets.append(packet)

            offset_param += self.__file_chunk_limit

        return tuple(packets)

    def __transfered_file_check_command_gen(self):
        command = bytes([0xFF, 0x13])
        file_check_code = 0x09
        payload = command + self.__password.encode("ASCII") + bytes([file_check_code])
        return self.__STX + bytes([len(payload)]) + payload

    def __packet_header_gen(self, payload: bytes):
        if len(payload) <= 255:
            header = self.__STX + bytes([len(payload)])
            return header
        else:
            header = self.__STX + bytes([0xFF])
            return header

    def send_json_products(self, data: dict) -> None:
        json_bytes = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        response: bytes
        self.__send(
            self.__initial_file_transfer_request_gen(json_bytes, clear_database=True),
            "Пакет, содержащий хэш-данные файла и параметры",
        )
        response, _ = self.__recv(force_exit_if_timeout=True)
        if response != b"\x02\x03\xff\x13\x00":
            logging.error(f"Не удалось инициализировать передачу JSON файла на весы.")
            sys.exit(1)
        packets = self.__file_transfer_commands_gen(json_bytes)
        for packet in packets:
            self.__send_big_data(packet, "Пакет, содержащий порцию файла")
            response, _ = self.__recv()
            if response == b"\x02\x03\xff\x13\x00":
                continue
            else:
                logging.error(f"Не удалось загрузить порцию файла.")
                sys.exit(1)
        while True:
            self.__send(
                self.__transfered_file_check_command_gen(),
                "Пакет с запросом на проверку отправляемого файла",
            )

            response, _ = self.__recv()
            if response == b"\x02\x06\xff\x13\x00\x01\x00\x00":
                time.sleep(1)
                continue
            elif response == b"\x02\x06\xff\x13\x00\x00\x00\x00":
                break
            elif response == b"\x02\x06\xff\x13\x00\x02\x00\x00":
                logging.error(f"Файл обработан с ошибкой.  Загрузка не удалась.")
                sys.exit(1)

    def get_all_json_receive_commands(self) -> dict:
        res = dict()
        res["1"] = self.__file_creation_request_gen()
        res["2"] = self.__file_creation_status_request_gen()
        res["3"] = self.__hash_calculating_request_gen()
        res["4"] = self.__hash_calculating_status_request_gen()
        res["5"] = self.__file_transfer_init_request_gen()
        return res

    def get_all_json_transfer_commands(self, json_bytes) -> dict:
        res = dict()
        res["1"] = self.__initial_file_transfer_request_gen(
            data=json_bytes, clear_database=True
        )
        res["2"] = self.__initial_file_transfer_request_gen(
            data=json_bytes, clear_database=False
        )
        res["3"] = self.__file_transfer_commands_gen(json_bytes)
        res["4"] = self.__transfered_file_check_command_gen()

        return res
