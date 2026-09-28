"""Importing an installed Throne copy the user points at: its `throne.db`
library and the traffic its `throne_stats.db` counted, which Qt keeps in tables
of its own for servers and for applications. Every value is synthetic."""
import json
import pathlib
import sqlite3
import tempfile
import time

from native_dialogs import file_dialog

GROUP = 21
PROFILE = 41
QT_DIRECT = -101
SCHEMA = '''
CREATE TABLE profiles(id INTEGER PRIMARY KEY,type TEXT NOT NULL,name TEXT,gid INTEGER NOT NULL,outbound_json TEXT NOT NULL);
CREATE TABLE groups(id INTEGER PRIMARY KEY,name TEXT NOT NULL,url TEXT,profiles_json TEXT,front_proxy_id INTEGER,landing_proxy_id INTEGER,info TEXT,archive INTEGER,skip_auto_update INTEGER,sub_last_update INTEGER);
CREATE TABLE groups_order(group_id INTEGER PRIMARY KEY,display_order INTEGER);
CREATE TABLE route_profiles(id INTEGER PRIMARY KEY,name TEXT NOT NULL,default_outbound_id INTEGER,raw_route TEXT,is_raw INTEGER);
CREATE TABLE route_rules(route_profile_id INTEGER,rule_order INTEGER,type INTEGER,domain_json TEXT,outbound TEXT,PRIMARY KEY(route_profile_id,rule_order));
CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE otp_profiles(id INTEGER PRIMARY KEY,name TEXT,secret TEXT,issuer TEXT);
CREATE TABLE entity_ids(profile_last_id INTEGER,group_last_id INTEGER);
'''
STATS_SCHEMA = '''
CREATE TABLE config_traffic_minute(bucket_start INTEGER NOT NULL,profile_id INTEGER NOT NULL,up INTEGER NOT NULL DEFAULT 0,down INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(bucket_start,profile_id));
CREATE TABLE config_traffic_hour(bucket_start INTEGER NOT NULL,profile_id INTEGER NOT NULL,up INTEGER NOT NULL DEFAULT 0,down INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(bucket_start,profile_id));
CREATE TABLE app_traffic_minute(bucket_start INTEGER NOT NULL,process_name TEXT NOT NULL,up INTEGER NOT NULL DEFAULT 0,down INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(bucket_start,process_name));
CREATE TABLE app_traffic_hour(bucket_start INTEGER NOT NULL,process_name TEXT NOT NULL,up INTEGER NOT NULL DEFAULT 0,down INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(bucket_start,process_name));
CREATE TABLE config_meta(profile_id INTEGER PRIMARY KEY,name TEXT,group_name TEXT,type TEXT,server_address TEXT,first_seen INTEGER NOT NULL DEFAULT 0,last_seen INTEGER NOT NULL DEFAULT 0);
CREATE TABLE app_meta(process_name TEXT PRIMARY KEY,last_path TEXT,first_seen INTEGER NOT NULL DEFAULT 0,last_seen INTEGER NOT NULL DEFAULT 0);
'''


def run(h):
    command, click, wait_for, js, check, screenshot = (
        h[k] for k in ('command', 'click', 'wait_for', 'js', 'check', 'screenshot'))
    initial = command('snapshot')
    hour = int(time.time()) // 3600 * 3600

    def settings_page():
        click('.primary-nav button:nth-child(5)')
        wait_for('return !!document.querySelector("[data-settings-section=backup]")')
        click('[data-settings-section=backup]')
        wait_for('return !!document.querySelector("#backup-open")')

    def stats():
        return command('trafficStats', {'days': 1, 'utcOffsetMinutes': 0})

    def library(root):
        db = sqlite3.connect(root / 'throne.db')
        db.executescript(SCHEMA)
        db.execute('INSERT INTO profiles VALUES(?,?,?,?,?)',
                   (PROFILE, 'socks', 'Database label', GROUP,
                    json.dumps({'type': 'socks', 'tag': 'Imported exit',
                                'server': '192.0.2.44', 'server_port': 1080})))
        db.execute('INSERT INTO groups VALUES(?,?,?,?,?,?,?,?,?,?)',
                   (GROUP, 'Imported team', '', json.dumps([PROFILE]), -1, -1, '', 0, 0, 0))
        db.execute('INSERT INTO groups_order VALUES(?,?)', (GROUP, 0))
        db.execute('INSERT INTO entity_ids VALUES(?,?)', (PROFILE, GROUP))
        db.commit()
        db.close()

    def counted(root):
        db = sqlite3.connect(root / 'throne_stats.db')
        db.executescript(STATS_SCHEMA)
        db.execute('INSERT INTO config_traffic_hour VALUES(?,?,?,?)', (hour, PROFILE, 1000, 2000))
        db.execute('INSERT INTO config_traffic_minute VALUES(?,?,?,?)', (hour + 60, PROFILE, 10, 20))
        db.execute('INSERT INTO config_traffic_hour VALUES(?,?,?,?)', (hour, QT_DIRECT, 7, 8))
        db.execute('INSERT INTO app_traffic_hour VALUES(?,?,?,?)', (hour, 'old-browser', 300, 400))
        db.execute('INSERT INTO app_meta VALUES(?,?,?,?)', ('old-browser', '/usr/bin/old-browser', 1, 2))
        db.execute('INSERT INTO config_meta VALUES(?,?,?,?,?,?,?)',
                   (PROFILE, 'Remembered exit', 'Remembered team', 'socks', '192.0.2.44', 1, 2))
        db.commit()
        db.close()

    with tempfile.TemporaryDirectory(prefix='thronium-throne-copy-') as folder:
        root = pathlib.Path(folder)
        library(root)
        counted(root)
        before_stats = stats()
        try:
            command('preferences', {**initial['preferences'], 'language': 'en', 'theme': 'dark'})
            wait_for('return document.documentElement.lang==="en"')
            settings_page()
            click('#backup-open')
            file_dialog('Open backup', root / 'throne.db', opening=True)
            wait_for('return !!document.querySelector("#backup-confirm")')
            check(js('return !!document.querySelector("#legacy-traffic-count")'),
                  'a chosen Throne library is read together with the traffic counted beside it')
            reported = js('return document.querySelector("#legacy-traffic-count").textContent')
            # Two server buckets (the minute row folds into its hour) and one
            # application bucket.
            check(reported.rstrip().endswith('3'),
                  'the review counts the hours of traffic it would take over: ' + reported)
            screenshot('throne-directory-review-en')
            review = js('return document.querySelector("#main-modal").textContent')
            click('#backup-acknowledge')
            click('#backup-confirm')
            wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')
            imported = next((p for p in command('snapshot')['profiles'] if p['name'] == 'Imported exit'), None)
            check(imported is not None and imported['address'] == '192.0.2.44',
                  'the library of the chosen copy is imported from its own database file: '
                  + json.dumps([{'name': p['name'], 'address': p.get('address')} for p in command('snapshot')['profiles']])
                  + ' review=' + review[:600])
            after = stats()
            rows = {row['id']: row for row in after['profiles']['rows']}
            check(imported['id'] in rows and rows[imported['id']]['upload'] == 1010
                  and rows[imported['id']]['download'] == 2020,
                  'traffic imported beside its server stays attached to the profile it belongs to')
            check(rows[imported['id']]['name'] == 'Imported exit',
                  'the imported server is named by the library, not by the old statistics row')
            direct = next((row for row in after['profiles']['rows'] if row['direct']), None)
            check(direct is not None and (direct['upload'], direct['download']) == (7, 8),
                  'what the old copy counted without a server stays Direct')
            applications = {row['process']: row for row in after['applications']['rows']}
            check('old-browser' in applications
                  and (applications['old-browser']['upload'], applications['old-browser']['download']) == (300, 400),
                  'the application table of the old copy is imported as its own')
            check((after['profiles']['upload'], after['profiles']['download']) == (1017, 2028)
                  and (after['applications']['upload'], after['applications']['download']) == (300, 400),
                  'the two tables keep their own totals instead of inflating each other')
            check(after['profiles']['series'][-1]['upload'] >= 1017,
                  'the imported hours reach the chart of the period they belong to')
            # Importing the same copy again leaves the same history behind.
            click('#backup-open')
            file_dialog('Open backup', root / 'throne.db', opening=True)
            wait_for('return !!document.querySelector("#backup-confirm")')
            click('#backup-acknowledge')
            click('#backup-confirm')
            wait_for('return !document.querySelector("dialog[open]") && !!document.querySelector("#backup-notice")')
            again = stats()
            # A second import is a second library: its server is a profile of its
            # own and carries its own hours. What does not depend on that mapping
            # — Direct and the application table — is simply taken over again.
            check(again['applications']['upload'] == after['applications']['upload']
                  and next(r for r in again['profiles']['rows'] if r['direct'])['upload'] == 7,
                  'rows that name no server of the library are taken over once, not twice')
            check(len([p for p in command('snapshot')['profiles'] if p['name'] == 'Imported exit']) == 2
                  and again['profiles']['upload'] == after['profiles']['upload'] + 1010,
                  'a second copy brings its own server and the hours that server counted')
            log = command('getLogs', {})
            check(any(entry.get('code') == 'traffic_history_imported' for entry in log['entries']),
                  'the journal records that traffic history was taken over')
        finally:
            settings_page()
            click('#backup-undo')
            wait_for('return !!document.querySelector("#backup-confirm")')
            click('#backup-acknowledge')
            click('#backup-confirm')
            wait_for('return !document.querySelector("dialog[open]")')
            command('clearTrafficHistory')
            command('preferences', initial['preferences'])
            assert before_stats['profiles']['upload'] >= 0
