from itertools import chain

from guillotina import app_settings


def get_rules():
    return chain(*app_settings["permissions"].values())
