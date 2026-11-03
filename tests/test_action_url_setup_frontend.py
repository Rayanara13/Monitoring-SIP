"""Run the panel's real setup code in Node with a small DOM/browser adapter."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="Node is needed for frontend behavior checks")
PANEL = Path(__file__).resolve().parent.parent / "panel.html"


def run_panel(body, catalog=None):
    source = PANEL.read_text(encoding="utf-8")
    program = "//" + source.split("// ── Action URL ─", 1)[1].split("// ── User info & init ─", 1)[0]
    # The fixed setup below is synthetic; no production token or phone data is read.
    catalog = catalog or [{"key": "incoming_call", "ru": "Входящий", "en": "Incoming Call",
                           "parameter": "action_url.incoming_call"}]
    harness = r'''
const assert = require('node:assert/strict');
const vm = require('node:vm');
const CATALOG = __CATALOG__;
const elements = new Map();
const element = id => {
  if (!elements.has(id)) elements.set(id, {value:'', innerHTML:'', textContent:'',
    disabled:false, hidden:false, dataset:{}, style:{}, classList:{add(){}, remove(){}, contains(){return false;}}});
  return elements.get(id);
};
element('aurl-host').value = '192.0.2.10:8000';
element('aurl-user').value = 'admin';
element('aurl-number').value = '101';
const browser = {
  console, URL, Blob, setTimeout(){return 1;}, clearTimeout(){},
  location:{hostname:'192.0.2.10',host:'192.0.2.10:8000',port:'8000',protocol:'http:'},
  currentUserInfo:{username:'admin',event_token:'synthetic-admin-token',is_admin:true},
  navigator:{clipboard:{async writeText(value){browser.copied = value;}}},
  window:{isSecureContext:true},
  document:{getElementById:element, body:{appendChild(){}},
    createElement(tag){return {style:{},click(){browser.downloaded=this;},remove(){},select(){}};},
    execCommand(){return true;}},
  $:element,
  esc(value){return String(value ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');},
  fetch:async()=>({ok:true,json:async()=>({events:[],phones:[]})})
};
vm.createContext(browser);
vm.runInContext(__PROGRAM__, browser);
vm.runInContext(`actionUrlEvents = ${JSON.stringify(CATALOG)};
  aurlUsers = [{username:'admin',event_token:'synthetic-admin-token'}, {username:'bob',event_token:'synthetic-bob-token'}];
  aurlPhones = [{number:'101',name:'Приёмная',ip:'192.0.2.11'}];
  aurlCatalogUser = 'admin'; aurlLoading = false;`, browser);
async function run() { __BODY__ }
run().catch(error=>{console.error(error);process.exitCode=1;});
'''
    script = harness.replace("__PROGRAM__", json.dumps(program), 1).replace("__CATALOG__", json.dumps(catalog), 1).replace("__BODY__", body, 1)
    result = subprocess.run(["node", "-"], input=script, text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_one_selected_card_is_literal_local_in_every_url():
    result = run_panel("""
      const url = vm.runInContext("actionUrlFor('incoming_call')", browser);
      console.log(JSON.stringify(url));
    """)
    assert "local=101&" in result
    assert "local=$active_user" not in result


def test_number_choice_is_required_and_auto_is_deliberate():
    result = run_panel("""
      element('aurl-number').value = '';
      assert.throws(()=>vm.runInContext("actionUrlFor('incoming_call')",browser), /[Вв]ыберите/);
      element('aurl-number').value = '__auto__';
      console.log(JSON.stringify(vm.runInContext("actionUrlFor('incoming_call')",browser)));
    """)
    assert "local=$active_user" in result


def test_origin_preserves_https_and_macros():
    result = run_panel("""
      element('aurl-host').value = 'https://sip.example.test:8443';
      console.log(JSON.stringify(vm.runInContext("actionUrlFor('incoming_call')", browser)));
    """)
    assert result.startswith("https://sip.example.test:8443/event?")
    assert "remote=$remote&called_number=$calledNumber" in result
    assert "model=$model&firmware=$firmware" in result


def test_shared_base_cannot_export_or_copy_one_handsets_number_for_all_events():
    result = run_panel("""
      vm.runInContext("aurlPhones.push({number:'102',ip:'192.0.2.11'})",browser);
      assert.throws(()=>vm.runInContext("actionUrlFor('incoming_call')",browser), /[Оо]бщий IP/);
      assert.throws(()=>vm.runInContext('buildActionUrlConfig()',browser), /[Оо]бщий IP/);
      element('aurl-number').value = '__auto__';
      console.log(JSON.stringify(vm.runInContext('buildActionUrlConfig()',browser)));
    """)
    assert "local=$active_user" in result
    assert "local=101" not in result


@pytest.mark.parametrize("host", ["http://user:pass@example.test", "http://example.test/path",
                                  "http://example.test?query=1", "ftp://example.test",
                                  "example.test\nattacker.test", "http://example.test#fragment"])
def test_server_input_cannot_inject_a_config_line_or_extra_url_parts(host):
    result = run_panel(f"""
      element('aurl-host').value = {json.dumps(host)};
      let rejected = false;
      try {{ vm.runInContext("actionUrlFor('incoming_call')",browser); }} catch(error) {{ rejected = true; }}
      console.log(JSON.stringify(rejected));
    """)
    assert result is True


def test_cfg_contains_all_api_parameters_and_same_fixed_number(srv):
    with srv.client.session_transaction() as session:
        session["username"] = "admin"
        session["logged_in"] = True
    catalog = srv.client.get("/action_url_events").get_json()["events"]
    config = run_panel("console.log(JSON.stringify(vm.runInContext('buildActionUrlConfig()', browser)));", catalog)
    lines = config.splitlines()
    assert lines[0] == "#!version:1.0.0.1"
    values = [line.split(" = ", 1) for line in lines[1:] if line]
    assert len(values) == 48
    assert {parameter for parameter, _ in values} == {event["parameter"] for event in catalog}
    assert all("local=101&" in value for _, value in values)


def test_cfg_rejects_urls_longer_than_phone_limit():
    result = run_panel("""
      vm.runInContext("aurlUsers[0].event_token = 'x'.repeat(512)",browser);
      let error = '';
      try { vm.runInContext('buildActionUrlConfig()',browser); } catch(e) { error = e.message; }
      console.log(JSON.stringify(error));
    """)
    assert "511" in result


def test_download_and_clipboard_actions_use_the_same_fixed_number_urls():
    result = run_panel("""
      browser.URL.createObjectURL = blob => { browser.cfgBlob = blob; return 'blob:synthetic'; };
      const button = {textContent:'Копировать',dataset:{}};
      await vm.runInContext('copyActionUrl(0, {textContent:"Копировать",dataset:{}})',browser);
      const copiedOne = browser.copied;
      await vm.runInContext('copyAllActionUrls({textContent:"Копировать",dataset:{}})',browser);
      const copiedAll = browser.copied;
      vm.runInContext('downloadActionUrlConfig()',browser);
      console.log(JSON.stringify({copiedOne,copiedAll,filename:browser.downloaded.download,
        config:await browser.cfgBlob.text()}));
    """)
    assert result["filename"] == "monitoring-sip-101.cfg"
    assert result["copiedOne"] in result["copiedAll"]
    assert "action_url.incoming_call = " + result["copiedOne"] in result["config"]


def test_cfg_rejects_missing_or_injected_parameter_names():
    result = run_panel("""
      vm.runInContext('delete actionUrlEvents[0].parameter',browser);
      assert.throws(()=>vm.runInContext('buildActionUrlConfig()',browser));
      browser.badParameter = ['action_url.incoming_call','account.1.password'].join(String.fromCharCode(10));
      vm.runInContext('actionUrlEvents[0].parameter = badParameter',browser);
      assert.throws(()=>vm.runInContext('buildActionUrlConfig()',browser));
      console.log(JSON.stringify(true));
    """)
    assert result is True


def test_catalog_failure_or_loading_prevents_using_previous_users_token():
    result = run_panel("""
      element('aurl-user').value = 'bob';
      let rejected = false;
      try { vm.runInContext("actionUrlFor('incoming_call')",browser); } catch(e) { rejected = true; }
      console.log(JSON.stringify(rejected));
    """)
    assert result is True


def test_out_of_order_catalog_response_cannot_restore_old_users_phones():
    result = run_panel("""
      const pending = [];
      browser.fetch = url => new Promise(resolve=>pending.push({url,resolve}));
      const first = vm.runInContext('loadActionUrlPhones()',browser);
      assert.equal(element('aurl-number').value,'');
      element('aurl-user').value = 'bob';
      const second = vm.runInContext('loadActionUrlPhones()',browser);
      pending[1].resolve({ok:true,json:async()=>({events:CATALOG, phones:[{number:'202',name:'Bob'}]})});
      await second;
      pending[0].resolve({ok:true,json:async()=>({events:CATALOG, phones:[{number:'101',name:'Admin'}]})});
      await first;
      console.log(JSON.stringify(vm.runInContext('({user:aurlCatalogUser,phones:aurlPhones,selection:$("aurl-number").value})',browser)));
    """)
    assert result["user"] == "bob"
    assert [phone["number"] for phone in result["phones"]] == ["202"]
    assert result["selection"] == ""


def test_unresolved_and_missing_peer_diagnostics_escape_phone_input():
    result = run_panel("""
      const unresolved = vm.runInContext('resolvedNote({number:""})',browser);
      const peer = vm.runInContext('remoteNote({key:"incoming_call",remote:"",raw_remote:"$remote<img>",model:"<script>"})',browser);
      console.log(JSON.stringify({unresolved,peer}));
    """)
    assert "настройк" in result["unresolved"].lower()
    assert "не подставил" in result["peer"].lower()
    assert "$remote&lt;img&gt;" in result["peer"]
    assert "<img>" not in result["peer"]


def test_phone_diagnostics_escape_raw_values_and_never_include_a_token():
    result = run_panel("""
      console.log(JSON.stringify(vm.runInContext('eventDiagnostics({raw_local:"<img>",raw_remote:"$remote",model:"<script>",firmware:"1.2",token:"must-not-be-rendered"})',browser)));
    """)
    assert "&lt;img&gt;" in result
    assert "&lt;script&gt;" in result
    assert "must-not-be-rendered" not in result
