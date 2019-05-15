import sqlite3
import logging, sys


# simple helper to make decent html tables from sqlite results
def html_table(res):
    html = ['<table>',]
    if len(res) > 0:
        html.append('<tr>')
        for k in res[0].keys():
            html.append('<th>{0}</th>'.format(k))
        html.append('</tr>')

        for r in res:
            html.append('<tr>')
            for k in r.keys():
                html.append('<td>{0}</td>'.format(r[k]))
            html.append('</tr>')
    else:
        html.append('<tr><th>no results</th></tr>')
    html.append('</table>')
    return '\n'.join(html)


# expects 'sql' and 'row'
# smart enough to execute or execute many depending on
# options being a dict or a list of dicts
def exec_sql(kwargs):
    ret = True
    try:
        logging.debug("Trying SQL:")
        logging.debug(kwargs['sql'])
        logging.debug(kwargs['options'])
        conn = sqlite3.connect(kwargs['options']['db'])
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        if isinstance(kwargs['options'], dict):
            cur.execute(kwargs['sql'], kwargs['options'])
        elif isinstance(kwargs['options', list]):
            cur.executemany(kwargs['sql'], kwargs['options'])
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f'*** sql oops: {0}', e.args[0])
        ret = False  # fail!
    ret = cur.fetchall()
    cur.close()
    conn.close()
    return ret

