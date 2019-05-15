import logging, sys
from sym_api_client_python.clients.sym_bot_client import SymBotClient
import json
import datetime
from lxml import html
from html import escape
import shlex
from sqlite_stuff import exec_sql
import regex
from time import time
from requests_toolbelt.multipart.encoder import MultipartEncoder
import base64

class DemoBotClient(SymBotClient):

    def __init__(self, auth, config):
        super().__init__(auth, config)
        self.commands = {
                        'd' : 'die',
                        'e' : 'exit',
                        'k' : 'kill',
                        'h' : 'help',
                        's' : 'send',
                        'l' : 'list',
                        'v' : 'view',
                        'a' : 'approve',
                        'p' : 'pending',
                        'kw' : 'keywords',
                        'ka': 'keyadd',
                        'kd': 'keydelete'
        }
        self.db = {'db' : 'atbpoc.db'}
        self.truncate = 10
        self.tmp = 'tmp'

    def process_message(self, im):
        logging.debug(f'***** process_message {im}')

        options = self.parseOptions(im)
        logging.debug(options)

        # short or long command flags
        for k,v in self.commands.items():
            if k in options:
                options[v] = options[k]
        logging.debug(options)

        if any (k in options for k in ('die', 'kill', 'exit')):
            logging.debug('SEPPUKU')
            sys.exit(0)

        if 'help' in options:
            msg = escape(json.dumps(self.commands, indent=4))
            sid = im['stream']['streamId']
            self.respond(sid, f'<pre>{msg}</pre>')

        if 'send' in options:
            text = self.getPlainTextMsg(im)
            logging.debug(f'text: {text}')

            recipients = self.getEmailsFromUserIds(
                            self.getMentionedUserIds(im))
            logging.debug(f'recipients: {recipients}')

            # load key words
            keywords = self.get_key_words()
            # search for matches
            matches = self.find_needles(keywords, text)

            conf = ''
            if matches:
                # these are symphony IDs
                approvers = self.get_approvers()

                # tell approver
                appr_str = super().get_stream_client().create_im(approvers)
                if 'id' in appr_str:
                    text = 'Please approve pending message.'
                    self.respond(appr_str['id'], text)

                conf = 'Message is pending approval before being sent.'

            else: #send message!
                self.forward_message(im)
                conf = 'Message forwarded.'

            # confirmation to sender
            self.respond(im['stream']['streamId'], conf)


    # takes a streamID and plaintext message
    def respond(self, sid, msg):
        logging.debug(f'responding to {sid}')
        msgDict = dict(message=f'<messageML>{msg}</messageML>')
        logging.debug(msgDict)
        super().get_message_client().send_msg(sid, msgDict)


    # crappy hack to only send one attachment at a time
    # but good enough for demo!
    def forward_message(self, im):
        logging.debug('forward_message')
        recipients = self.getMentionedUserIds(im)
        if recipients:
            stream = super().get_stream_client().create_im(recipients)
        if 'id' in stream:
                stream_id = stream['id']
                msg = self.getPlainTextMsg(im)

                paths = self.get_attachments_paths(im)
                if paths:
                    for file_name in paths:
                        file_content = paths[file_name]
                        url = '/agent/v4/stream/{0}/message/create'.format(stream_id)
                        data = MultipartEncoder(
                            fields={'message': f'<messageML>{msg}</messageML>',
                            'attachment': (file_name, file_content, 'file')})
                        headers = {
                            'Content-Type': data.content_type
                        }
                        super().execute_rest_call("POST", url, data=data, headers=headers)
                else:
                    # no attachments
                    self.respond(stream_id, msg)


    # store attachments locally and return a dict of filenames -> paths
    def get_attachments_paths(self, im):
        logging.debug('get_attachments_paths')
        attachments = self.getFromMsgAsDict(im, 'attachments')
        stream = self.getFromMsgAsDict(im, 'stream')
        stream_id = stream['streamId']
        msg_id = im['messageId']
        ret = {}
        if attachments:
            for a in attachments.values():
                file_name = a['name']
                file_id = a['id']
                logging.debug(f'get_msg_attachments: \
                              {stream_id}, {msg_id}, {file_id}')
                #att =   super().get_message_client().get_msg_attachments(stream_id, msg_id, file_id)
                # hack because API is BROKE !!!!!!!!!!!
                url = '/agent/v1/stream/{0}/attachment'.format(stream_id)
                params = {
                    'messageId': msg_id,
                    'fileId': file_id
                }
                agentHost = self.config.data['agentHost']
                session = super().get_agent_session()
                response = session.request(
                                            "GET", 
                                            agentHost + url, 
                                            params=params
                                            )
                #assume name is unique!
                ret[file_name] = base64.b64decode(response.content) 
        return ret


    # this is so bloody clever and I have no idea how it works
    # add '--' to the end of args (which is a list of the cmd line args)
    # iterates over the tuples of the args as k,v
    # IF k starts with a '-'
    # and for each k,v
    # IF k starts with a '-' remove it and use as key
    # IF v starts with a '-' remove it and use as value,
    # otherwise use TRUE as value
    # options is therefore a DICTIONARY of k,v pairs whereby
    # the flag is key and the value is arg after the flag
    # (or TRUE if the flag was followed by another flag)
    # make sure it doesn't treat negative numbers like command flags!
    # by checking if its a digit after '-' -- this will choke on floats oh well
    def parseOptions(self, im):
        txt = self.getPlainTextMsg(im)
        args = shlex.split(txt)
        return {k.strip('-'):
                True if (v.startswith('-')
                         and not v.strip('-').isdigit()) else v
                for k, v in zip(args, args[1:] + ['--']) if
                (k.startswith('-') and not k.strip('-').isdigit())}

    # strip all the HTML etc out of the message
    def getPlainTextMsg(self, im):
        txt = ''
        try:
            root = html.fromstring(im['message'])
            txt = root.text_content()
            # extract span class="entity" text to get name
            names = root.xpath("//span[@class='entity']")
            for name in names:
                # kill @names
                txt = txt.replace(name.text_content(), '')
        except KeyError as err:
            logging.debug("Oops: {0}".format(err))
        except:
            logging.debug("Oops: {0}".format(sys.exec_info()[0]))
        return txt.strip()


    # returns list of mentioned userIds
    def getMentionedUserIds(self, im):
        data = self.getFromMsgAsDict(im, 'data')
        return self.getDataByTypes(data,
                                   'com.symphony.user.userId',
                                   'com.symphony.user.mention')


    # extract a part of the message as a dict for easier processing
    def getFromMsgAsDict(self, im, wot='message'):
        if wot in im:
            if isinstance(im[wot], dict): # is a dict
                return im[wot]
            elif isinstance(im[wot], list): # list of dicts
                # make a dict where key is integer from 0, val is dict
                return dict((im[wot].index(d), d) for d in im[wot])
            elif isinstance(im[wot], str): # str so json load it
                return json.loads(im[wot])
            else:
                return json.loads(im[wot]) # i guess?! i dunno...


    # extract specific data as LIST via the (optional) type and idType
    # passed in args
    def getDataByTypes(self, data, ti, t):
        ret = []
        for dictn in data.values():
            if not t:
                t = dictn['type'] # lame hack to make the below line work
            if dictn['type'] == t:
                for id in dictn['id']:
                    if id['type'] == ti:
                        ret.append(id['value'])
        return ret

    # sym UserId -> email
    # returns a LIST
    def getEmailsFromUserIds(self, userIds):
        logging.debug(f'getEmailsFromUserIds {userIds}')
        res = super().get_user_client().get_users_from_id_list(userIds)
        emails = []
        for r in res['users']:
            emails.append(r['emailAddress'])
        return emails


    # returns a LIST of keywords from database
    def get_key_words(self, active=1):
        logging.debug('get_key_words')

        options = {'active' : active}
        options.update(self.db)
        sql = '''\
select keyword from keywords\
'''
        if active == 1:
            sql = sql + ' where active = 1'

        kwargs = {'options' : options, 'sql' : sql}
        res = exec_sql(kwargs)
        keyWords = []
        if res:
            for r in res:
                keyWords.extend(r)
        logging.debug(f'keyWords: {keyWords}')
        return keyWords

    # see if ANY of the items in LIST needles is in string haystack
    def find_needles(self, needles, haystack):
        logging.debug(f'find_needles')

        prog = regex.compile('('+'|'.join(needles)+')', regex.IGNORECASE)
        result = prog.search(haystack)
        logging.debug(f'result: {result}')
        return result # if no matches returns None


    def get_approvers(self):
        logging.debug('get_approvers')

        options = {}
        options.update(self.db)
        sql = '''\
select approvers from approvers where active = 1
'''
        kwargs = {'options' : options, 'sql' : sql}
        res = exec_sql(kwargs)
        emails = []
        if res:
            for r in res:
                emails.extend(r)
        ret = super().get_user_client().get_users_from_email_list(emails)
        users = ret['users']
        logging.debug(f'users: {users}')
        return users

