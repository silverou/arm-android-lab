'use strict';
/*
 * Message-driven Lua runner (no timers): host posts {type:'cmd', action,
 * tag?, chunk?}; script executes and writes result to a file, replies via
 * send(). Host pings to verify liveness. Created before resume.
 *
 * OTP substitution: chunk containing __OTP__ reads /data/local/tmp/otp.txt.
 */
var OUT_DIR = '/data/user/0/com.ihuman.pinyin/files/';
var OTP_PATH = '/data/local/tmp/otp.txt';
var luaStatePtr = null;
var luaFns = {};
var executed = {};
var pings = 0;

function findAny(name) {
  var mods = [];
  try { mods = Process.enumerateModules(); } catch (e) { return null; }
  try { var g = Module.getGlobalExportByName(name); if (g && !g.isNull()) return g; } catch (e) {}
  for (var i = 0; i < mods.length; i++) {
    try { var q = mods[i].findExportByName(name); if (q && !q.isNull()) return q; } catch (e) {}
  }
  return null;
}

function writeFile(path, txt) {
  for (var i = 0; i < 3; i++) {
    try {
      var f = new File(path, 'w');
      f.write(txt);
      f.flush();
      f.close();
      return true;
    } catch (e) {}
  }
  return false;
}

function grabState() {
  if (luaStatePtr) return true;
  ['luaL_loadbuffer', 'lua_pcall', 'lua_tolstring'].forEach(function (n) {
    if (luaFns[n]) return;
    var q = findAny(n);
    if (q) luaFns[n] = q;
  });
  if (!luaFns['luaL_loadbuffer'] || !luaFns['lua_pcall'] || !luaFns['lua_tolstring']) return false;
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      try {
        var ps = mods[i].findExportByName('_ZN13LuaJavaBridge10s_luaStateE');
        if (!ps || ps.isNull()) {
          if (/libcocos2dlua/.test(mods[i].name || '')) ps = mods[i].base.add(0x25f9cd8);
        }
        if (ps && !ps.isNull()) {
          var p = ps.readPointer();
          if (!p.isNull()) { luaStatePtr = p; return true; }
        }
      } catch (e) {}
    }
  } catch (e) {}
  return false;
}

function execute(tag, chunk) {
  var code = chunk;
  if (code.indexOf('__OTP__') >= 0) {
    var otp = '';
    try { otp = File.readAllText(OTP_PATH).trim(); } catch (e) {}
    if (!otp) { writeFile(OUT_DIR + 'out_' + tag + '.txt', 'ERR:no OTP file'); return; }
    code = code.split('__OTP__').join(otp);
  }
  var codeStr = Memory.allocUtf8String(code);
  var fnLoad = new NativeFunction(luaFns['luaL_loadbuffer'], 'int', ['pointer', 'pointer', 'size_t', 'pointer']);
  var fnPcall = new NativeFunction(luaFns['lua_pcall'], 'int', ['pointer', 'int', 'int', 'int']);
  var nm = Memory.allocUtf8String('=luarpc');
  var r = fnLoad(luaStatePtr, codeStr, code.length, nm);
  if (r !== 0) { writeFile(OUT_DIR + 'out_' + tag + '.txt', 'ERR:load ' + r); return; }
  var rc = fnPcall(luaStatePtr, 0, 1, 0);
  try {
    var fnToStr = new NativeFunction(luaFns['lua_tolstring'], 'pointer', ['pointer', 'int', 'pointer']);
    var szp = Memory.alloc(8);
    var ps = fnToStr(luaStatePtr, -1, szp);
    if (ps.isNull()) { writeFile(OUT_DIR + 'out_' + tag + '.txt', 'ERR:nostr rc=' + rc); return; }
    var len = szp.readU64().toNumber();
    var txt = ps.readUtf8String(Math.min(len, 60000)) || '';
    writeFile(OUT_DIR + 'out_' + tag + '.txt', 'OK:' + rc + ':' + txt);
  } catch (e2) {
    writeFile(OUT_DIR + 'out_' + tag + '.txt', 'ERR:read ' + String(e2));
  }
}

function handle(msg) {
  try {
    if (msg.action === 'ping') {
      pings++;
      send({ ev: 'pong', n: pings, lua: grabState() ? 1 : 0, done: Object.keys(executed).join(',') });
    } else if (msg.action === 'run') {
      var tag = msg.tag;
      var chunk = msg.chunk;
      if (executed[tag]) { send({ ev: 'already', tag: tag }); return; }
      if (!grabState()) { send({ ev: 'nolua', tag: tag }); return; }
      try {
        execute(tag, chunk);
      } catch (e) {
        writeFile(OUT_DIR + 'out_' + tag + '.txt', 'ERR:exc ' + String(e));
      }
      executed[tag] = true;
      send({ ev: 'ran', tag: tag });
    }
  } catch (e) {
    send({ ev: 'handler_err', e: String(e) });
  } finally {
    recv('cmd', handle);
  }
}

recv('cmd', handle);
send({ ev: 'rpc_up' });
