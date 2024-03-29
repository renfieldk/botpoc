import logging, sys
from sym_api_client_python.clients.sym_bot_client import SymBotClient
import json
import datetime
from lxml import html
from html import escape
import shlex
from sqlite_stuff import exec_sql,html_table
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

        sid = im['stream']['streamId']

        if any (k in options for k in ('die', 'kill', 'exit')):
            logging.debug('SEPPUKU')
            sys.exit(0)

        isApprover = False
        user = self.getFromMsgAsDict(im, 'user')
        if self.isUserApprover(user):
            isApprover = True


        if 'help' in options:
#            msg = escape(json.dumps(self.commands, indent=4))
#            self.respond(sid, f'<pre>{msg}</pre>')
            html = html_table([self.commands,])
            self.respond(sid, html)

        elif 'send' in options:
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
                # save message
                self.save_message(im)

                self.send_to_approvers('Please approve <hash tag="pending" /> message.')

                conf = 'Message is pending approval before being sent.'

            else: #send message!
                self.forward_message(im)
                conf = 'Message forwarded.'

            # confirmation to sender
            self.respond(im['stream']['streamId'], conf)

        elif 'pending' in options:
            logging.debug('pending')
            if isApprover:
                ls = self.get_pending_list()
                self.respond(sid, ls)
            else:
                self.respond(sid, 'You are not an approver.')

        elif 'approve' in options:
            logging.debug('approve')
            if isApprover:
                # record approval first
                self.approve_message(options['approve'], user)
                # retrieve message
                ret_message = self.get_message(options['approve'])
                # forward message
                if (ret_message):
                    self.forward_message(ret_message)
                # tell approver it's sent
                self.respond(sid, 'Message forwarded!')

        elif 'list' in options:
            logging.debug('list')
            list = self.get_my_messages(user['email'])
            self.respond(sid, list)

        elif 'view' in options:
            logging.debug('view')
            this_msg = self.get_message(options['view'])
            plain_txt = self.getPlainTextMsg(this_msg)
            self.forward_msg_to_stream(this_msg, sid)
            #self.respond(sid, plain_txt)

        elif 'keywords' in options:
            logging.debug('keywords')
            if isApprover:
                html = html_table(self.get_keywords())
                self.respond(sid, html)
            else:
                self.respond(sid, "You are not authorized.")

        elif 'keyadd' in options:
            logging.debug('add keyword')
            if isApprover:
                self.add_keyword(options['keyadd'])
                html = html_table(self.get_keywords())
                self.respond(sid, html)
            else:
                self.respond(sid, "You are not authorized.")

        elif 'keydelete' in options:
            logging.debug('delete keyword')
            if isApprover:
                self.delete_keyword(options['keydelete'])
                html = html_table(self.get_keywords())
                self.respond(sid, html)
            else:
                self.respond(sid, "You are not authorized.")

    def get_message(self, msg_no):
        logging.debug('get_message')

        if msg_no == True: # not specified
            msg_no = -1

        options = {'msg_no' : msg_no}
        options.update(self.db)

        sql = '''\
select * from messages where id = :msg_no
'''
        kwargs = {'options' : options, 'sql' : sql}
        res = exec_sql(kwargs)
        if len(res) > 0:
            msgDict = json.loads(res[0]['msg'])
            logging.debug(f'got message: {msgDict}')
            return msgDict
        else:
            return {}

    def approve_message(self, msg_no, user):
        logging.debug('approve_message')

        if msg_no == True: # not specified
            msg_no = -1

        options = {'msg_no' : msg_no,
                   'approver' : user['email']}
        options.update(self.db)

        sql = '''\
update messages set  approver = :approver, \
approved = datetime('now') \
                where id = :msg_no\
'''
        kwargs = {'options' : options, 'sql' : sql}
        res = exec_sql(kwargs)
        logging.debug(f'results: {res}')
        return res


    def send_to_approvers(self, msg):
            # these are symphony IDs
            approvers = self.get_approvers()
            appr_ids = [user['id'] for user in approvers]
            emails = [user['emailAddress'] for user in approvers]
            recs = ', '.join([f'<mention email="{e}" />' for e in emails])
            msg = f'{recs}<br />{msg}'

            # tell approvers
            appr_str = super().get_stream_client().create_im(appr_ids)
            if 'id' in appr_str:
                self.respond(appr_str['id'], msg)

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
            self.forward_msg_to_stream(im, stream['id'])


    def forward_msg_to_stream(self, im, stream_id):
        plain = self.getPlainTextMsg(im)
        user = self.getFromMsgAsDict(im, 'user')
        displayName = user['displayName']
        msg = f'From: {displayName}<br />'
        userIds = self.getMentionedUserIds(im)
        emails = self.getEmailsFromUserIds(userIds)
        for e in emails:
            msg = f'{msg}To:<mention email=\"{e}\" /><br />'
        msg = f'{msg}{plain}'

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
        logging.debug('getPlainTextMsg')
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

    def save_message(self, im):
        logging.debug('save_message')
        options = { 'msg' : json.dumps(im),
                    'messageId' : im['messageId'],
                    'sender' : im['user']['email'],
                    'senttime' : im['timestamp']}
        options.update(self.db)
        sql = '''\
insert into messages ('messageId','msg', 'sender','senttime') values \
(:messageId, :msg, :sender, :senttime)\
'''
        kwargs = {'options' : options, 'sql' : sql}
        return exec_sql(kwargs)

    def get_pending_list(self):
        options = {}
        options.update(self.db)
        sql = '''\
select * from messages where approved is null order by id DESC
'''
        kwargs = {'options' : options, 'sql' : sql}
        res = exec_sql(kwargs)
        modres = []
        for r in res:
            row = {}
            for k in r.keys():
                row[k] = r[k]
            msg = self.getPlainTextMsg(json.loads(r['msg']))
            row['msg'] = msg[:self.truncate] + '...'
            row['messageId'] = r['messageId'][:self.truncate] + '...'
            row['senttime'] = datetime.datetime.fromtimestamp(r['senttime']/1000.0)
            modres.append(row)
        return html_table(modres)

    def get_my_messages(self, sender):
        options = {'sender' : sender,
                   'count' : 20}
        options.update(self.db)
        sql = '''\
select * from messages where sender = :sender order by id DESC limit :count
'''
        kwargs = {'options' : options, 'sql' : sql}
        res = exec_sql(kwargs)
        modres = []
        for r in res:
            row = {}
            for k in r.keys():
                row[k] = r[k]
            msg = self.getPlainTextMsg(json.loads(r['msg']))
            row['msg'] = msg[:self.truncate] + '...'
            row['messageId'] = r['messageId'][:self.truncate] + '...'
            row['senttime'] = datetime.datetime.fromtimestamp(r['senttime']/1000.0)
            modres.append(row)
        return html_table(modres)


    def isUserApprover(self, user):
        if 'email' in user:
            return self.isEmailApprover(user['email'])
        elif 'emailAddress' in user:
            return self.isEmailApprover(user['emailAddress'])
        else:
            return False


    # checks if the email in the message is an approver
    def isEmailApprover(self, email):
        logging.debug('isEmailApprover')
        approvers = self.get_approvers()
        return email in [r['emailAddress'] for r in approvers]


    def get_approvers(self):
        logging.debug('get_approvers')
        options = {}
        options.update(self.db)
        sql = '''\
select approvers from approvers where active = 1
'''
        kwargs = {'options' : options, 'sql' : sql}
        res = exec_sql(kwargs)
        approvers = []
        if res:
            for r in res:
                approvers.extend(r)
        logging.debug(f'approvers: {approvers}')
        users = self.getUsersFromEmails(approvers)
        logging.debug(f'users: {users}')
        return users['users']


    def getUsersFromEmails(self, emails):
        logging.debug('getUsersFromEmails')
        res = super().get_user_client().get_users_from_email_list(emails)
        logging.debug(f'res: {res}')
        return res

    def get_keywords(self, active=1):
        logging.debug('get_keywords')
        options = {'active' : active}
        options.update(self.db)
        sql = '''\
select keyword from keywords\
'''
        if active == 1:
            sql = sql + ' where active = 1'

        kwargs = {'options' : options, 'sql' : sql}
        res = exec_sql(kwargs)
        logging.debug(f'keywords:{res}')
        return res


    def delete_keyword(self, kw):
        logging.debug('delete keyword')
        options = {}
        options.update(self.db)
        options['keyword'] = kw
        options['active'] = 0
        sql = '''\
update keywords set active = :active where keyword = :keyword\
'''
        kwargs = {'options' : options, 'sql' : sql}
        res = exec_sql(kwargs)
        return res


    def add_keyword(self, addme):
        kw = self.get_keywords(0) #gets ALL including inactive
        options = {}
        options.update(self.db)
        options['keyword'] = addme
        options['active'] = 1
        sql = ''
        if addme not in kw:
            sql = '''\
insert into keywords ('keyword', 'active') values (:keyword, :active)\
'''
        else:
            sql = '''\
update keywords set active = :active where keyword = :keyword\
'''
        kwargs = {'options' : options, 'sql' : sql}
        res = exec_sql(kwargs)
        return res
