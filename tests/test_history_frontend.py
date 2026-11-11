"""Exercise the panel's history requests and rendering with synthetic data."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="Node is needed for frontend behavior checks")
PANEL = Path(__file__).resolve().parent.parent / "panel.html"


def run_history(test):
    source = PANEL.read_text(encoding="utf-8")
    history = source.split("// ── History ──", 1)[1].split("// ── Accounts ──", 1)[0]
    format_duration = re.search(r"^function _fmtDur\(sec\) \{.*?^\}", source, re.M | re.S).group()
    harness = r'''
const assert = require('node:assert/strict');
const vm = require('node:vm');
const elements = new Map();
const $ = id => {
  if (!elements.has(id)) elements.set(id, {
    value: '', textContent: '', innerHTML: '', disabled: true, options: [],
    replaceChildren(...options) { this.options = options; this.value = options[0].value; }
  });
  return elements.get(id);
};
const response = data => ({ ok: true, json: async () => data });
const browser = {
  $, currentUserInfo: {is_admin: true}, URLSearchParams,
  Option: function(text, value) { this.text = text; this.value = value; },
  esc: value => String(value ?? ''), location: {href: '/'}
};
vm.createContext(browser);
vm.runInContext(__PROGRAM__, browser);
async function test() { __TEST__ }
test().catch(error => { console.error(error); process.exitCode = 1; });
'''
    script = harness.replace("__PROGRAM__", json.dumps(format_duration + "\n//" + history)).replace("__TEST__", test)
    result = subprocess.run(["node", "-"], input=script, encoding="utf-8", capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr


def test_history_admin_filter_and_sqlite_row_fields():
    run_history("""
      const requestPaths = [];
      browser.fetch = async path => {
        requestPaths.push(path);
        if (path === '/admin/users') return response({ok: true, users: [{username: 'a & b'}]});
        return response({records: [
          {username: 'a & b', local: '0101', remote: '0102', duration: 0, direction: 'in'},
          {username: 'a & b', local: '0101', remote: '0103', duration: 65, direction: 'out'},
        ], total: 2});
      };
      await browser.loadHistoryUsers();
      assert.deepEqual($('hist-user').options.map(option => option.value), ['', 'a & b']);
      $('hist-user').value = 'a & b';
      browser.syncHistoryNumbers([{number: '0101', name: 'Room'}]);
      $('hist-number').value = '0101';
      browser.syncHistoryNumbers([{number: '0101', name: 'Lobby'}, {number: '0102', name: 'Office'}]);
      assert.equal($('hist-number').value, '0101');
      assert.equal($('hist-number').options[1].text, '0101 — Lobby');
      await browser.loadHistory();
      assert.equal(requestPaths.at(-1), '/history?page=1&per_page=25&number=0101&username=a+%26+b');
      assert.match($('hist-body').innerHTML, />00:00<\\/td>/);
      assert.match($('hist-body').innerHTML, />01:05<\\/td>/);
      assert.match($('hist-body').innerHTML, />a & b<\\/td>/);
    """)


def test_history_ignores_out_of_order_requests_and_disables_pagination_when_empty():
    run_history("""
      browser.currentUserInfo = {is_admin: false};
      const pending = [];
      browser.fetch = path => new Promise(resolve => pending.push({path, resolve}));
      const initial = browser.loadHistory();
      pending[0].resolve(response({records: [{local: '101'}], total: 80}));
      await initial;
      assert.equal($('hist-next').disabled, false);
      const older = browser.histPage(1);
      assert.equal(pending[1].path, '/history?page=2&per_page=25');
      $('hist-number').value = '102';
      const newer = browser.loadHistory();
      assert.equal(pending[2].path, '/history?page=1&per_page=25&number=102');
      pending[2].resolve(response({records: [], total: 0}));
      await newer;
      pending[1].resolve(response({records: [{local: '101'}], total: 80}));
      await older;
      assert.match($('hist-body').innerHTML, /Нет звонков/);
      assert.equal($('hist-prev').disabled, true);
      assert.equal($('hist-next').disabled, true);
      const failed = browser.loadHistory();
      pending[3].resolve({ok: false, status: 500});
      await failed;
      assert.match($('hist-body').innerHTML, /Не удалось загрузить историю/);
    """)
