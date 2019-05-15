import logging, sys
from sym_api_client_python.configure.configure import SymConfig
from sym_api_client_python.auth.rsa_auth import SymBotRSAAuth
from sym_api_client_python.clients.sym_bot_client import SymBotClient
from i_listen_to_im import IListenToIMs
from demobot_client import DemoBotClient

def main():
    if 'DEBUG' in sys.argv:
        logging.basicConfig(format='%(asctime)s %(message)s',
                            level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(asctime)s %(message)s',
                            level=logging.INFO)

    configure = SymConfig('./config.json')
    configure.load_rsa_config()
    auth = SymBotRSAAuth(configure)
    auth.authenticate()

    bot_client = DemoBotClient(auth, configure)

    datafeed_event_service = bot_client.get_datafeed_event_service()

    im_ear = IListenToIMs(bot_client)
    datafeed_event_service.add_im_listener(im_ear)

    logging.debug('starting datafeed...')
    datafeed_event_service.start_datafeed()


if __name__ == "__main__":
    main()
