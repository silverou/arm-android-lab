'use strict';
/*
 * Internal-loader recon probe.
 *
 * 1) List libcocos2dlua symbols matching undump/parser/load/decode patterns
 *    (40953 symbols exist; we filter, chunked send).
 * 2) Hook AAssetManager_open + AAsset_read (libandroid) — the engine reads
 *    APK-internal .ihi through these; log asset name + first bytes of every
 *    read so we can identify the .ihi stream and the decrypt boundary.
 */
var done1 = false, done2 = false;

function sendList(tag, arr, chunk) {
  for (var i = 0; i < arr.length; i += chunk) {
    send({ ev: tag, i: i, n: arr.slice(i, i + chunk) });
  }
}

function listSyms() {
  if (done1) return;
  var m = null;
  try {
    Process.enumerateModules().forEach(function (x) {
      if (!m && /libcocos2dlua/.test(x.name)) m = x;
    });
  } catch (e) {}
  if (!m) return;
  done1 = true;
  var syms;
  try { syms = m.enumerateSymbols(); } catch (e) { send({ ev: 'sym_err', e: String(e) }); return; }
  var want = [];
  var re = /undump|luaU_|f_parser|protectedparser|luaD_|luaZ|loadAux|dofile|require|decode|Decode|decrypt|Decrypt|xtea|Xtea/i;
  syms.forEach(function (s) {
    if (s.type !== 'function') return;
    if (re.test(s.name)) want.push(s.name + '@' + s.address.toString());
  });
  send({ ev: 'sym_count', total: syms.length, want: want.length });
  sendList('syms', want, 40);
}

function hookAssets() {
  if (done2) return;
  var open = null, read = null;
  try { open = Module.getGlobalExportByName('AAssetManager_open'); } catch (e) {}
  try { read = Module.getGlobalExportByName('AAsset_read'); } catch (e) {}
  if (!open || !read) { send({ ev: 'asset_miss', open: !!open, read: !!read }); done2 = true; return; }
  done2 = true;
  var fnRead = new NativeFunction(read, 'int', ['pointer', 'pointer', 'int']);

  Interceptor.attach(open, {
    onEnter: function (a) {
      try { this.nm = a[1].readCString(); } catch (e) { this.nm = ''; }
    },
    onLeave: function (ret) {
      try {
        if (!ret.isNull() && /\.ihi/.test(this.nm)) {
          send({ ev: 'asset_open', n: String(this.nm).slice(0, 140), fd: ret.toString() });
          this.asset = ret;
        }
      } catch (e) {}
    }
  });
  send({ ev: 'asset_hooked' });

  Interceptor.attach(read, {
    onEnter: function (a) {
      this.buf = a[0]; this.sz = a[2].toInt32();
    },
    onLeave: function (ret) {
      try {
        var got = ret.toInt32();
        if (got > 8 && this.buf && !this.buf.isNull()) {
          var head = new Uint8Array(this.buf.readByteArray(Math.min(got, 32)));
          var hex = '';
          for (var i = 0; i < head.length; i++) hex += ('0' + head[i].toString(16)).slice(-2);
          send({ ev: 'asset_read', got: got, head: hex });
        }
      } catch (e) {}
    }
  });
}

var tries = 0;
var poll = setInterval(function () {
  tries++;
  listSyms();
  hookAssets();
  if ((done1 && done2) || tries > 100) clearInterval(poll);
}, 100);
