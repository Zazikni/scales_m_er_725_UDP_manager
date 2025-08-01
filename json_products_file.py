import json
import socket
import time
from pprint import pprint
from typing import Optional
import logging
from settings import SCALE_IP, SCALE_PORT, SCALE_PASSWORD

STX = 0x02


def file_creation_request_gen(stx, password) -> bytes:
    command = bytes([0xFF, 0x14])
    payload = command + password.encode("ascii")
    return (
        bytes(
            [
                stx,
                len(payload),
            ]
        )
        + payload
    )


def file_creation_status_request(stx, password) -> bytes:
    command = bytes([0xFF, 0x15])
    payload = command + password.encode("ASCII")
    return (
        bytes(
            [
                stx,
                len(payload),
            ]
        )
        + payload
    )


def hash_calculating_request_gen(stx, password) -> bytes:
    command = bytes([0xFF, 0x12])
    hash_calc_code = 0x06
    payload = command + password.encode("ASCII") + bytes([hash_calc_code])
    return (
        bytes(
            [
                stx,
                len(payload),
            ]
        )
        + payload
    )


def hash_calculating_status_request(stx, password) -> bytes:
    command = bytes([0xFF, 0x12])
    hash_calc_code = 0x07
    payload = command + password.encode("ASCII") + bytes([hash_calc_code])
    return (
        bytes(
            [
                stx,
                len(payload),
            ]
        )
        + payload
    )


def file_transfer_init_request_gen(stx, password) -> bytes:
    command = bytes([0xFF, 0x12])
    hash_calc_code = 0x03
    payload = command + password.encode("ASCII") + bytes([hash_calc_code])
    return (
        bytes(
            [
                stx,
                len(payload),
            ]
        )
        + payload
    )


def send(sock: socket.socket, host: str, port: int, data: bytes, label: str):
    logging.debug(f"[>] {label} | {len(data)} байт | HEX: {data.hex()} | {data}")
    sock.sendto(data, (host, port))


def recv_big_data(
    sock: socket.socket, timeout: float = 5.0
) -> Optional[tuple[bytes, tuple]]:
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(65507)
        logging.debug(
            f"[<] От весов {addr[1]} → {sock.getsockname()[1]} | {len(data)} байт | {list(data[:13])}"
        )
        return data, addr
    except socket.timeout:
        return None


def recv(sock: socket.socket, timeout: float = 5.0) -> Optional[tuple[bytes, tuple]]:
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(2048)
        logging.debug(
            f"[<] От весов {addr[1]} → {sock.getsockname()[1]} | {len(data)} байт | HEX: {data.hex()} | {data} | {list(data)}"
        )
        return data, addr
    except socket.timeout:
        return None


def get_json_from_bytearray(data: bytes) -> dict | None:
    """
    Преобразует байтовую строку в JSON-словарь.
    Если получен список, он будет обёрнут в словарь под ключом 'items'.

    :param data: байтовые данные, содержащие JSON.
    :return: словарь JSON или None в случае ошибки.
    """
    try:
        json_str = data.decode("utf-8")
        parsed = json.loads(json_str)

        if isinstance(parsed, dict):
            result = parsed
        elif isinstance(parsed, list):
            result = {"items": parsed}
        else:
            print("Получен неизвестный тип JSON:", type(parsed))
            return None

        # print("JSON-словарь получен:")
        # print(json.dumps(result, indent=2, ensure_ascii=False))
        return result

    except Exception as e:
        logging.error("Ошибка декодирования JSON:", e)
        return None


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        # s.connect((SCALE_IP, SCALE_PORT))
        send(
            s,
            SCALE_IP,
            SCALE_PORT,
            file_creation_request_gen(STX, SCALE_PASSWORD),
            "Пакет с запросом на создание файла",
        )
        recv(s)

        while True:
            send(
                s,
                SCALE_IP,
                SCALE_PORT,
                file_creation_status_request(STX, SCALE_PASSWORD),
                "Пакет с запросом на получение статуса создания файла",
            )
            time.sleep(1)
            data_from_scales = recv(s)
            if data_from_scales[0][4] == 172:
                continue
            else:
                # print("Data is ready to collect")
                break
        send(
            s,
            SCALE_IP,
            SCALE_PORT,
            hash_calculating_request_gen(STX, SCALE_PASSWORD),
            "Пакет с запросом на начало расчёта хэш-данных",
        )
        recv(s)
        # Если код статуса расчёта = 0
        # TODO Сделать обработку случая когда статус рассчета != 0
        send(
            s,
            SCALE_IP,
            SCALE_PORT,
            hash_calculating_status_request(STX, SCALE_PASSWORD),
            "Пакет с запросом на получение статуса расчёта хэш-данных",
        )
        recv(s)

        file_data = bytearray()
        while True:
            send(
                s,
                SCALE_IP,
                SCALE_PORT,
                file_transfer_init_request_gen(STX, SCALE_PASSWORD),
                "Пакет с запросом на получение порции файла",
            )
            data, address = recv_big_data(s, 30)
            is_last_chunk = data[5] == 1
            file_data.extend(data[12:])
            # 6-й байт (по спецификации): флаг последней порции
            if is_last_chunk:
                break
        scales_data = get_json_from_bytearray(file_data)
        pprint(scales_data["products"])
