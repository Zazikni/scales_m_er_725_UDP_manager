import logging
from pprint import pprint

from scales import Scales
from settings import SCALE_IP, SCALE_PORT, SCALE_PASSWORD

if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG)
    scales = Scales(SCALE_IP, SCALE_PORT, SCALE_PASSWORD)
    products = scales.get_products_json()
    # pprint(products)
    scales.send_json_products(products)
