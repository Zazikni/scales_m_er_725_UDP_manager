import logging
import datetime

from scales import Scales
from settings import SCALE_IP, SCALE_PORT, SCALE_PASSWORD
from datetime import datetime, timedelta


def update_dates(product: dict) -> dict:
    today = datetime.now()
    shelf_life_days = product.get("shelfLifeInDays", 0)
    date_format = "%d-%m-%y"
    product["manufactureDate"] = today.strftime(date_format)
    product["sellByDate"] = (today + timedelta(days=shelf_life_days)).strftime(
        date_format
    )
    return product


if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG)
    scales = Scales(SCALE_IP, SCALE_PORT, SCALE_PASSWORD)
    products = scales.get_products_json()
    for product in products["products"]:
        product = update_dates(product)
    scales.send_json_products(products)
