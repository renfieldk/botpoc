import logging, sys, inspect
from sym_api_client_python.listeners.im_listener import IMListener

class IListenToIMs(IMListener):
    def __init__(self, sbc):
        self.bot_client = sbc

    def on_im_message(self, im):
        logging.debug('on_im_message')
        self.bot_client.process_message(im)

    def on_im_created(self, im):
        logging.debug('on_im_created')
        self.bot_client.process_message(im)
