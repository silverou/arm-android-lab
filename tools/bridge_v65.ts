
import Java from 'frida-java-bridge';
const PKG = 'com.ihuman.pinyin';
const VENDOR_B64 = 'MIIDkTCCAnmgAwIBAgIELcJ83DANBgkqhkiG9w0BAQsFADB5MQswCQYDVQQGEwJjbjEQMA4GA1UECBMHYmVpamluZzEQMA4GA1UEBxMHYmVpamluZzEbMBkGA1UEChMSd2FubWVpd2VpbGFpamlhb3l1MRswGQYDVQQLExJ3YW5tZWl3ZWlsYWlqaWFveXUxDDAKBgNVBAMTA3lqcTAeFw0xNzAyMTYwNzQ0MDRaFw00MjAyMTAwNzQ0MDRaMHkxCzAJBgNVBAYTAmNuMRAwDgYDVQQIEwdiZWlqaW5nMRAwDgYDVQQHEwdiZWlqaW5nMRswGQYDVQQKExJ3YW5tZWl3ZWlsYWlqaWFveXUxGzAZBgNVBAsTEndhbm1laXdlaWxhaWppYW95dTEMMAoGA1UEAxMDeWpxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArjSF9qaN6fgEfuwS3zCmdziZ0Nr/wCsPZyjQ+j+N+rkjlrCawZ6hkEwobmQ0wZFXSyI8gdaoSPGJBscsnOXoqhv/83HO+w1g/zBV9XjqPBl/po0v73OcBRx3u8A0KKE1nMa9pa9ge/4iLQorphpBtXCWXXH2Z4/DIsaTTyR652Ex9EmRyu6eA+I4e8pVePhIqbLKkXqZCvWWjR0Vaj3XBqFgQjAOFBa5BCJDRxqJq9RopXhQAKwu6W6OcVM7g/nJlvrpWztdKkyi3TEfQ6vzNE/YkQ+0MHf2YQ0wrH0AnhUrk7zQdRXbjXX540lzfxNDlkZEoxkN7MbbPKFy2iP1uQIDAQABoyEwHzAdBgNVHQ4EFgQUBMVCpheq98WKUB7yT+V0HXdU9XAwDQYJKoZIhvcNAQELBQADggEBACZ+dkyO0hZZX2UhzZ97pcTw4HfvJhdXR2Uz8c6Bmbab0bH+woaMPDn3Ma08SqHO+gVTDU5HwJdjRzg+rUjMHm/IQ9eFSkFbOkTCpL/R7wIAVYaY2hnNNeCWMoXcffzkgUxfOpcQ2QWd6RmH5yr+q2w2yuwmS1rgIGxeWZPIOnSJK53/JulwU3lvVG+pWXZc2/DShspEB7GQsCQxobULLZPiSEZgW9C61jxPpWrEmDT+HDSjPW9fmTslTmXpQmZtui4IL2FvW0ZpuIxty5F+kD7KG35KTsnulxHkdh6WelvE4mNMFkzo1AHQS6oifkI/ir9K94G7ioPoBgPw6qd95Rk=';

// ===== 原生文件探测黑名单（词表全量）=====
const BLACK = [
  '/sbin/su', '/su/bin/su', '/su', '/data/local/xbin/su', '/data/local/bin/su',
  '/data/local/su', '/system/xbin/su', '/system/bin/su', '/system/sd/xbin/su',
  '/system/bin/failsafe/su', '/system/bin/cufsdosck', '/system/xbin/cufsdosck',
  '/system/bin/cufsmgr', '/system/xbin/cufsmgr', '/system/bin/cufaevdd',
  '/system/xbin/cufaevdd', '/system/bin/conbb', '/system/xbin/conbb',
  'androVM', 'mount.vboxsf', 'libGLES_emulation', 'libGLESv1_CM_emulation',
  'libGLESv2_emulation', '/system/bin/qemu_props', 'microvirtd', 'microvirt-prop',
  '/system/bin/nox', 'nox-prop', 'nox-vbox-sf', 'nox-setprop',
  'libdroid4x', 'droid4x', 'ttVM', 'tiantianVM', 'nemuVM',
  'bstcmd_shim', 'bstfolderd', 'bstsyncfs', '.bluestacks.prop', 'libGLES_bst',
  'xposed', 'saurik.substrate', 'frida-server', 'libsubstrate-dvm', 'libxhook',
  'mumu-configs', 'libmemtrack_real'
];
function badPath(p: string): boolean {
  for (let i = 0; i < BLACK.length; i++) if (p.indexOf(BLACK[i]) >= 0) return true;
  return false;
}
// v58: libmsaoaidsec's ELF constructor crashes deterministically during the
// packer's second-stage dlopen wave (wild list pointer, reproducible on our
// stack). The MSA OAID ad-id SDK is irrelevant to resources/gameplay — deny
// its load and let the packer take its missing-lib path.
function armDlDeny(): void {
  const DENY = [/libmsaoaidsec/i];
  const tag = function (nm: string): boolean {
    for (let i = 0; i < DENY.length; i++) if (DENY[i].test(nm)) return true;
    return false;
  };
  // v59: the constructor crash happens INSIDE dlopen — onLeave never runs, so
  // the deny must happen in onEnter: rewrite the soname to a nonexistent lib
  // (persistent buffer) so dlopen fails cleanly before any constructor.
  const denyBuf = Memory.alloc(128);
  denyBuf.writeUtf8String('/data/local/tmp/.no_such_lib_404.so');
  ['android_dlopen_ext', 'dlopen', '__loader_dlopen', '__loader_android_dlopen_ext'].forEach(function (sym) {
    try {
      const p = Module.getGlobalExportByName(sym);
      Interceptor.attach(p, {
        onEnter: function (a) {
          try {
            const nm = a[0].readCString();
            if (nm && nm.indexOf('libcocos2dlua') >= 0) startCtorPoll();
            if (nm && tag(nm)) {
              send('DL-DENY ' + nm);
              a[0] = denyBuf;
            }
          } catch (e) {}
        },
        onLeave: function (r) {
          try { if (r.isNull()) {} } catch (e) {}
        }
      });
    } catch (e) {}
  });
  // v62: the XXTEA key is likely set inside cocos ELF constructors, before
  // ART resolves JNI_OnLoad. JS timers run on frida's own thread, so a fast
  // poll started at cocos dlopen onEnter keeps running while the linker is
  // inside do_dlopen — attach the moment the exports appear.
  const CTOR_SYMS = ['_ZN7cocos2d8LuaStack14setHongenKAndSEPKciS2_i',
                     '_ZN7cocos2d8LuaStack18setXXTEAKeyAndSignEPKciS2_i',
                     '_ZN7cocos2d10FileUtils18setXXTEAKeyAndSignEPKciS2_i'];
  const ctorArmed: any = {};
  function armCtorHooks(): void {
    try {
      const mods0 = Process.enumerateModules();
      for (let si = 0; si < CTOR_SYMS.length; si++) {
        const SY = CTOR_SYMS[si];
        if (ctorArmed[SY]) continue;
        let addr0: any = null;
        for (let mi0 = 0; mi0 < mods0.length && !addr0; mi0++) {
          try {
            const e0 = mods0[mi0].findExportByName(SY);
            if (e0 && !e0.isNull() && mods0[mi0].name.indexOf('cocos') >= 0) addr0 = e0;
          } catch (ee0) {}
        }
        if (addr0) {
          ctorArmed[SY] = true;
          Interceptor.attach(addr0, {
            onEnter: function (aa) {
              try {
                const keyLen = aa[1].toInt32();
                const signLen = aa[3].toInt32();
                let key = '';
                let sign = '';
                let keyHex = '';
                if (keyLen > 0 && keyLen < 4096) {
                  const ku = new Uint8Array(aa[0].readByteArray(keyLen));
                  for (let i = 0; i < ku.length; i++) key += String.fromCharCode(ku[i]);
                  keyHex = Array.from(ku).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
                }
                if (signLen > 0 && signLen < 4096) {
                  const su = new Uint8Array(aa[2].readByteArray(signLen));
                  for (let j = 0; j < su.length; j++) sign += String.fromCharCode(su[j]);
                }
                send({ ev: 'XXTEA_KEY', via: 'ctor:' + SY.split('8')[1], key: key, keyLen: keyLen, sign: sign, signLen: signLen, keyHex: keyHex });
              } catch (e2) { send({ ev: 'keyhook_err', via: 'ctor', e: String(e2) }); }
            }
          });
          send('ctor-armed ' + SY);
        }
      }
    } catch (e) {}
  }
  // v63: poll ONLY inside the cocos dlopen window (v62's always-on 1ms poll
  // starved the JS thread and killed the session during script loading).
  let ctorPolling = false;
  function startCtorPoll(): void {
    if (ctorPolling) return;
    ctorPolling = true;
    let tries = 0;
    const iv = setInterval(function () {
      tries++;
      try {
        const m = Process.findModuleByName('libcocos2dlua.so');
        if (m) {
          for (let si = 0; si < CTOR_SYMS.length; si++) {
            const SY = CTOR_SYMS[si];
            if (ctorArmed[SY]) continue;
            try {
              const e0 = m.findExportByName(SY);
              if (e0 && !e0.isNull()) {
                ctorArmed[SY] = true;
                Interceptor.attach(e0, {
                  onEnter: function (aa) {
                    try {
                      const keyLen = aa[1].toInt32();
                      const signLen = aa[3].toInt32();
                      let key = '';
                      let sign = '';
                      let keyHex = '';
                      if (keyLen > 0 && keyLen < 4096) {
                        const ku = new Uint8Array(aa[0].readByteArray(keyLen));
                        for (let i = 0; i < ku.length; i++) key += String.fromCharCode(ku[i]);
                        keyHex = Array.from(ku).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
                      }
                      if (signLen > 0 && signLen < 4096) {
                        const su = new Uint8Array(aa[2].readByteArray(signLen));
                        for (let j = 0; j < su.length; j++) sign += String.fromCharCode(su[j]);
                      }
                      send({ ev: 'XXTEA_KEY', via: 'ctor', sym: SY, key: key, keyLen: keyLen, sign: sign, signLen: signLen, keyHex: keyHex });
                    } catch (e2) { send({ ev: 'keyhook_err', via: 'ctor', e: String(e2) }); }
                  }
                });
                send('ctor-armed-in-poll ' + SY);
              }
            } catch (ee) {}
          }
        }
      } catch (e) {}
      if (tries > 1500) clearInterval(iv);
    }, 1);
  }
  send('dl-deny armed (onEnter) + ctor-poll(triggered)');
}

function hookNative(): void {
  const fopenP = Module.getGlobalExportByName('fopen');
  Interceptor.attach(fopenP, {
    onEnter: function (a) {
      try { this.b = badPath(a[0].readCString()); } catch (e) { this.b = false; }
    },
    onLeave: function (r) { if (this.b) r.replace(ptr(0)); }
  });
  const accessP = Module.getGlobalExportByName('access');
  Interceptor.attach(accessP, {
    onEnter: function (a) {
      try { this.b = badPath(a[0].readCString()); } catch (e) { this.b = false; }
    },
    onLeave: function (r) { if (this.b) r.replace(-1); }
  });
  // v65: serve a STATIC fake /proc/self/fd — the second stage's fd sweep kept
  // picking up fds created during its own scan (endless growth). A fixed list
  // (0..40 empty files in the app cache) terminates the sweep. Names are all
  // numeric; readlink/fstat on absent ones simply ENOENTs, like closed fds.
  try {
    const FDR = '/data/user/0/com.ihuman.pinyin/cache/.fd/';
    const JF = Java.use('java.io.File');
    JF.$new(FDR).mkdirs();
    for (let fi = 0; fi <= 40; fi++) {
      try { JF.$new(FDR + fi).createNewFile(); } catch (e) {}
    }
    send('fd-dir built');
    const FDR_PTR = Memory.allocUtf8String(FDR);
    const opendirPP = Module.getGlobalExportByName('opendir');
    Interceptor.attach(opendirPP, {
      onEnter: function (a) {
        try {
          const p = a[0].readCString();
          if (p === '/proc/self/fd' || p === '/proc/self/fd/') {
            a[0] = FDR_PTR;
            send('fd-dir redirected');
          }
        } catch (e) {}
      }
    });
    send('fd-dir redirect armed');
  } catch (e: any) { send('fd-dir-err ' + e); }
  const openatP = Module.getGlobalExportByName('openat');
  Interceptor.attach(openatP, {
    onEnter: function (a) {
      try { this.b = badPath(a[1].readCString()); } catch (e) { this.b = false; }
    },
    onLeave: function (r) { if (this.b) r.replace(-1); }
  });
  const faccessatP = Module.getGlobalExportByName('faccessat');
  if (faccessatP) Interceptor.attach(faccessatP, {
    onEnter: function (a) {
      try { this.b = badPath(a[1].readCString()); } catch (e) { this.b = false; }
    },
    onLeave: function (r) { if (this.b) r.replace(-1); }
  });
  const statxP = Module.getGlobalExportByName('statx');
  if (statxP) Interceptor.attach(statxP, {
    onEnter: function (a) {
      try { this.b = badPath(a[2].readCString()); } catch (e) { this.b = false; }
    },
    onLeave: function (r) { if (this.b) r.replace(-1); }
  });
  send('native-blacklist armed (' + BLACK.length + ' patterns)');
}




function armLogger(): void {
  const seen: any = {};
  function log(kind: string, p: string) {
    const k = kind + p;
    if (seen[k]) return; seen[k] = 1;
    if (p.indexOf('/dev/') === 0 || p.indexOf('/apex/') === 0) return;
    send(kind + ' :: ' + p);
  }
  const fopenP = Module.getGlobalExportByName('fopen');
  Interceptor.attach(fopenP, { onEnter: function (a) { try { const p = a[0].readCString(); if (p[0] === '/') log('FOPEN', p); } catch (e) {} } });
  const openatP = Module.getGlobalExportByName('openat');
  Interceptor.attach(openatP, { onEnter: function (a) { try { const p = a[1].readCString(); if (p[0] === '/') log('OPENAT', p); } catch (e) {} } });
  const opendirP = Module.getGlobalExportByName('opendir');
  if (opendirP) Interceptor.attach(opendirP, { onEnter: function (a) { try { log('OPENDIR', a[0].readCString()); } catch (e) {} } });
  send('logger armed');
}



function armStatusRedirect(): void {
  const fopenC = new NativeFunction(Module.getGlobalExportByName('fopen'), 'pointer', ['pointer','pointer']);
  const fgetsC = new NativeFunction(Module.getGlobalExportByName('fgets'), 'pointer', ['pointer','int','pointer']);
  const fcloseC = new NativeFunction(Module.getGlobalExportByName('fclose'), 'int', ['pointer']);
  const opendirC = new NativeFunction(Module.getGlobalExportByName('opendir'), 'pointer', ['pointer']);
  const readdirC = new NativeFunction(Module.getGlobalExportByName('readdir'), 'pointer', ['pointer']);
  const closedirC = new NativeFunction(Module.getGlobalExportByName('closedir'), 'int', ['pointer']);
  const readlinkC = new NativeFunction(Module.getGlobalExportByName('readlink'), 'long', ['pointer', 'pointer', 'long']);

  // v38: pin at ARM time, BEFORE any hook is attached — plain read, no
  // reentrancy and no bypass flag. All later self/task reads replay the pin.
  // (v31/v36/v37 carried a wrong fclose NativeFunction signature 'int' that
  // threw "expected an integer" on every read() — the whole fake-content
  // chain silently died. Fixed here.)
  let pinned = false;
  let pinStatus = '';
  let pinStat = '';
  let pinV = '1';
  let dA = 0;
  let dF = 0;
  let dO = 0;
  let dR = 0;
  let reading = false;
  let dM = 0;

  function read(path: string): string {
    reading = true;
    try {
      const fp = fopenC(Memory.allocUtf8String(path), Memory.allocUtf8String('r'));
      if (fp.isNull()) return '';
      const buf = Memory.alloc(8192); let out = '';
      while (!fgetsC(buf, 8192, fp).isNull()) out += buf.readCString();
      fcloseC(fp);
      return out;
    } finally {
      reading = false;
    }
  }

  // v42 race probe: REAL task count at each key moment — if 0xdead9001 is the
  // dropper's raw-syscall enum vs our pinned Threads mismatch, survivors show
  // rc==V and deaths rc!=V at the status redirect.
  function realTids(withComm: boolean): any {
    const out: any = { n: 0, comms: [] };
    reading = true;
    try {
      const dir = opendirC(Memory.allocUtf8String('/proc/self/task'));
      if (!dir.isNull()) {
        const names: string[] = [];
        for (let i = 0; i < 120; i++) {
          const d = readdirC(dir);
          if (d.isNull()) break;
          try { names.push(d.add(19).readCString()); } catch (e) {}
        }
        closedirC(dir);
        for (let i = 0; i < names.length; i++) {
          const nm = names[i];
          if (!nm || nm === '.' || nm === '..') continue;
          out.n++;
          if (withComm) {
            let c = '?';
            try {
              const fp = fopenC(Memory.allocUtf8String('/proc/self/task/' + nm + '/comm'), Memory.allocUtf8String('r'));
              if (!fp.isNull()) {
                const buf = Memory.alloc(64);
                if (!fgetsC(buf, 64, fp).isNull()) c = buf.readCString();
                fcloseC(fp);
              }
            } catch (e) {}
            out.comms.push(nm + ':' + c);
          }
        }
      }
    } catch (e) { out.err = 1; }
    reading = false;
    return out;
  }

  function pinNow(): void {
    const s = read('/proc/self/status');
    if (!s) { send('pin-read-fail'); return; }
    const st = read('/proc/self/stat');
    let ps = s
      .replace(/^Name:.*$/m, 'Name:\tm.ihuman.pinyin')
      .replace(/^TracerPid:.*$/m, 'TracerPid:\t0');
    const m = ps.match(/^Threads:\t(\d+)/m);
    pinV = m ? m[1] : '1';
    if (st) {
      const parts = st.split(' ');
      if (parts.length > 19) parts[19] = pinV;
      pinStat = parts.join(' ');
    }
    pinStatus = ps;
    pinned = true;
    const rc = realTids(false);
    send('self-pin V=' + pinV + ' slen=' + pinStatus.length + ' statlen=' + pinStat.length + ' rc=' + rc.n);
    const rc2 = realTids(true);
    send('pin-comms ' + rc2.comms.join(','));
  }
  pinNow();

  const mainPid = Process.id.toString();
  const memfdCreate = new NativeFunction(Module.getGlobalExportByName('memfd_create'), 'int', ['pointer','int']);
  const writeC = new NativeFunction(Module.getGlobalExportByName('write'), 'long', ['int', 'pointer', 'long']);
  const closeC = new NativeFunction(Module.getGlobalExportByName('close'), 'int', ['int']);

  // v43: DYNAMIC Threads — every served status/stat carries the LIVE real
  // count so the dropper's raw-syscall enum (0xdead9000 group) always agrees
  // with what libc readers see. A frozen pin (V) drifted (22→24) and died.
  function dynStatus(base: string, live: number): string {
    return base.replace(/^Threads:\t\d+/m, 'Threads:\t' + live);
  }
  function dynStat(base: string, live: number): string {
    const parts = base.split(' ');
    if (parts.length > 19) parts[19] = String(live);
    return parts.join(' ');
  }

  function contentFor(tid: string, kind: string): string {
    if (kind === 'comm') return 'm.ihuman.pinyin\n';
    if (!pinned) return '';
    const live = realTids(false).n;
    if (kind === 'status') {
      return dynStatus(pinStatus
        .replace(/^Pid:.*$/m, 'Pid:\t' + tid)
        .replace(/^Tgid:.*$/m, 'Tgid:\t' + mainPid), live);
    }
    return tid + ' (m.ihuman.pinyin) S ' + mainPid + ' ' + mainPid +
      ' 0 0 -1 4194528 0 0 0 0 0 0 0 0 0 0 ' + live +
      ' 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0' + String.fromCharCode(10);
  }
  const memfdOf = (content: string, name: string): number => {
    if (!content) return -1;
    const fd = memfdCreate(Memory.allocUtf8String(name), 0);
    if (fd < 0) { send('memfd-fail ' + name); return -1; }
    writeC(fd, Memory.allocUtf8String(content), content.length);
    return fd;
  };
  // v44: path strings must outlive the allocating listener — frida frees
  // Memory.alloc made inside onEnter before the real syscall runs (trace only
  // ever saw garbage where '/proc/self/fd/N' should be; kernel reads the same
  // freed bytes → racy ENOENT → shell's status read fails → 0xdead9001).
  // Persistent ring buffers allocated at arm time; writeUtf8String per call.
  const ringBufs: any[] = [];
  for (let ri = 0; ri < 8; ri++) ringBufs.push(Memory.alloc(96));
  let ringI = 0;
  const setPath = (a: any, idx: number, fd: number): void => {
    const b = ringBufs[ringI];
    ringI = (ringI + 1) & 7;
    b.writeUtf8String('/proc/self/fd/' + fd);
    a[idx] = b;
  };
  const redirectTo = (a: any, idx: number, tid: string, kind: string, st: any): void => {
    const fd = memfdOf(contentFor(tid, kind), 'x' + tid + kind.charAt(0));
    if (fd >= 0) {
      setPath(a, idx, fd);
      st.mfd = fd;
      if (dR < 40) { dR++; send('RED-x ' + tid + ' ' + kind + ' fd' + fd); }
    }
  };
  const redirectToSelf = (a: any, idx: number, kind: string, st: any): void => {
    if (!pinned) return;
    const live = realTids(false).n;
    const content = kind === 'status' ? dynStatus(pinStatus, live) : dynStat(pinStat, live);
    const fd = memfdOf(content, 'self' + kind.charAt(0));
    if (fd >= 0) {
      setPath(a, idx, fd);
      st.mfd = fd;
      if (dR < 40) {
        dR++;
        send('RED-self ' + kind + ' fd' + fd + ' V=' + pinV + ' live=' + live);
      }
    }
  };
  // v39: maps scrubbing — the .ss dropper carries '/proc/self/maps' + 'frida'
  // strings and scans for the agent; serve a filtered copy (drop our traces).
  const MAPS_RE = /frida|gum-js|gum\b|logd_helper|linjector|memfd:frida/i;
  function isMapsPath(p: string): boolean {
    return p.indexOf('/proc/') === 0 && /\/maps$/.test(p);
  }
  function mapsContent(): string {
    const raw = read('/proc/self/maps');
    if (!raw) return '';
    const lines = raw.split('\n');
    const out: string[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (lines[i] && !MAPS_RE.test(lines[i])) out.push(lines[i]);
    }
    if (out.length) out.push('');
    return out.join('\n');
  }
  const redirectMaps = (a: any, idx: number, st: any): void => {
    const fd = memfdOf(mapsContent(), 'mp');
    if (fd >= 0) {
      setPath(a, idx, fd);
      st.mfd = fd;
      if (dM < 20) { dM++; send('MAPS-serve fd' + fd); }
    }
  };

  const openatP = Module.getGlobalExportByName('openat');
  Interceptor.attach(openatP, {
    onEnter: function (a) {
      this.mfd = -1;
      if (reading) return;
      try {
        const p = a[1].readCString();
        if (dA < 25) { dA++; send('AEN ' + p); }
        if (isMapsPath(p)) redirectMaps(a, 1, this);
        else if (p === '/proc/self/status') redirectToSelf(a, 1, 'status', this);
        else if (p === '/proc/self/stat') redirectToSelf(a, 1, 'stat', this);
        else if (p.indexOf('/proc/self/task/') === 0) {
          const sl = p.split('/task/')[1];
          if (sl) {
            const tid = sl.split('/')[0];
            if (p.indexOf('/status') > 0) redirectTo(a, 1, tid, 'status', this);
            else if (p.indexOf('/stat') > 0 && p.indexOf('/status') < 0) redirectTo(a, 1, tid, 'stat', this);
            else if (p.indexOf('/comm') > 0) redirectTo(a, 1, tid, 'comm', this);
          }
        }
      } catch (e) {}
    },
    onLeave: function () { if (this.mfd >= 0) closeC(this.mfd); }
  });
  const fopenP = Module.getGlobalExportByName('fopen');
  Interceptor.attach(fopenP, {
    onEnter: function (a) {
      this.mfd = -1;
      if (reading) return;
      try {
        const p = a[0].readCString();
        if (dF < 25) { dF++; send('FEN ' + p); }
        if (isMapsPath(p)) redirectMaps(a, 0, this);
        else if (p === '/proc/self/status') redirectToSelf(a, 0, 'status', this);
        else if (p === '/proc/self/stat') redirectToSelf(a, 0, 'stat', this);
        else if (p.indexOf('/proc/self/task/') === 0) {
          const sl = p.split('/task/')[1];
          if (sl) {
            const tid = sl.split('/')[0];
            if (p.indexOf('/status') > 0) redirectTo(a, 0, tid, 'status', this);
            else if (p.indexOf('/stat') > 0 && p.indexOf('/status') < 0) redirectTo(a, 0, tid, 'stat', this);
            else if (p.indexOf('/comm') > 0) redirectTo(a, 0, tid, 'comm', this);
          }
        }
      } catch (e) {}
    },
    onLeave: function () { if (this.mfd >= 0) closeC(this.mfd); }
  });
  const openPerP = Module.getGlobalExportByName('open');
  Interceptor.attach(openPerP, {
    onEnter: function (a) {
      this.mfd = -1;
      if (reading) return;
      try {
        const p = a[0].readCString();
        if (dO < 25) { dO++; send('OEN ' + p); }
        if (isMapsPath(p)) redirectMaps(a, 0, this);
        else if (p === '/proc/self/status') redirectToSelf(a, 0, 'status', this);
        else if (p === '/proc/self/stat') redirectToSelf(a, 0, 'stat', this);
        else if (p.indexOf('/proc/self/task/') === 0) {
          const sl = p.split('/task/')[1];
          if (sl) {
            const tid = sl.split('/')[0];
            if (p.indexOf('/status') > 0) redirectTo(a, 0, tid, 'status', this);
            else if (p.indexOf('/stat') > 0 && p.indexOf('/status') < 0) redirectTo(a, 0, tid, 'stat', this);
            else if (p.indexOf('/comm') > 0) redirectTo(a, 0, tid, 'comm', this);
          }
        }
      } catch (e) {}
    },
    onLeave: function () { if (this.mfd >= 0) closeC(this.mfd); }
  });
  send('v65 static-fd-dir armed (mainPid=' + mainPid + ')');
}

function armTaskCountMask(): void {
  const fopenC = new NativeFunction(Module.getGlobalExportByName('fopen'), 'pointer', ['pointer','pointer']);
  const fgetsC = new NativeFunction(Module.getGlobalExportByName('fgets'), 'pointer', ['pointer','int','pointer']);
  const fcloseC = new NativeFunction(Module.getGlobalExportByName('fclose'), 'int', ['pointer']);
  function readSelf(path: string): string {
    const fp = fopenC(Memory.allocUtf8String(path), Memory.allocUtf8String('r'));
    if (fp.isNull()) return '';
    const buf = Memory.alloc(2048); let out = '';
    while (!fgetsC(buf, 2048, fp).isNull()) out += buf.readCString();
    fcloseC(fp);
    return out;
  }
  const fridaRe = /frida|gum|gmain|gdbus/i;
  const badTids: any = {};
  let totalT = 0;
  try {
    const File = Java.use('java.io.File');
    const dir = File.$new('/proc/self/task');
    const names = dir.list();
    totalT = names.length;
    let badnames: any = {};
    for (let i = 0; i < names.length; i++) {
      const tid = String(names[i]);
      const cf = File.$new('/proc/self/task/' + tid + '/comm');
      const br = Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(cf));
      const line = String(br.readLine());
      br.close();
      if (fridaRe.test(line)) { badTids[tid] = true; badnames[tid] = line; }
    }
    send('threads total=' + names.length + ' bad=' + JSON.stringify(badnames));
  } catch (e: any) { send('sample-err ' + e); }

  const selfStatus = readSelf('/proc/self/status');
  let fakeSelf = selfStatus
    .replace(/^Name:.*$/m, 'Name:\tm.ihuman.pinyin')
    .replace(/^TracerPid:.*$/m, 'TracerPid:\t0')
    .replace(/^Threads:.*$/m, 'Threads:\t' + (totalT - Object.keys(badTids).length).toString());
  const CACHEP = '/data/user/0/com.ihuman.pinyin/cache/';
  const sp = CACHEP + 'self_status.txt';
  const FileWriter = Java.use('java.io.FileWriter');
  let fw = FileWriter.$new(sp, false); fw.write(fakeSelf, 0, fakeSelf.length); fw.close();
  const mainPid = Process.id.toString();
  const fakeStat = mainPid + ' (m.ihuman.pinyin) S ' + mainPid + ' ' + mainPid + ' 0 0 -1 4194528 0 0 0 0 0 0 0 0 0 0 ' + (totalT - Object.keys(badTids).length) + ' 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0' + String.fromCharCode(10);
  const sp2 = CACHEP + 'self_stat.txt';
  let fw2 = FileWriter.$new(sp2, false); fw2.write(fakeStat, 0, fakeStat.length); fw2.close();

  const SELF_STATUS = Memory.allocUtf8String(sp);
  const SELF_STAT = Memory.allocUtf8String(sp2);
  const openatP = Module.getGlobalExportByName('openat');
  Interceptor.attach(openatP, {
    onEnter: function (a) {
      try {
        const p = a[1].readCString();
        if (p === '/proc/self/status') a[1] = SELF_STATUS;
        else if (p === '/proc/self/stat') a[1] = SELF_STAT;
      } catch (e) {}
    }
  });
  const fopenP = Module.getGlobalExportByName('fopen');
  Interceptor.attach(fopenP, {
    onEnter: function (a) {
      try {
        const p = a[0].readCString();
        if (p === '/proc/self/status') a[0] = SELF_STATUS;
        else if (p === '/proc/self/stat') a[0] = SELF_STAT;
      } catch (e) {}
    }
  });
  const openSelfP = Module.getGlobalExportByName('open');
  Interceptor.attach(openSelfP, {
    onEnter: function (a) {
      try {
        const p = a[0].readCString();
        if (p === '/proc/self/status') a[0] = SELF_STATUS;
        else if (p === '/proc/self/stat') a[0] = SELF_STAT;
      } catch (e) {}
    }
  });

  // ===== 伪造 /proc/self/task 目录树 =====
  const FAKE_TASK = '/data/user/0/com.ihuman.pinyin/cache/faketask/';
  const faket = Java.use('java.io.File');
  const FileWriter2 = Java.use('java.io.FileWriter');
  try {
    const oldDir = faket.$new(FAKE_TASK);
    const olds = oldDir.list();
    if (olds) { for (let i = 0; i < olds.length; i++) { const sub = faket.$new(FAKE_TASK + String(olds[i])); const fs = sub.list(); if (fs) for (let j = 0; j < fs.length; j++) faket.$new(FAKE_TASK + String(olds[i]) + '/' + String(fs[j])).delete(); sub.delete(); } }
    oldDir.mkdirs();
    const dir = faket.$new('/proc/self/task');
    const names = dir.list();
    let cnt = 0;
    const cleanN = names.length - Object.keys(badTids).length;
    for (let i = 0; i < names.length; i++) {
      const tid = String(names[i]);
      if (tid in badTids) continue;
      const sub = faket.$new(FAKE_TASK + tid);
      sub.mkdirs();
      let s = selfStatus
        .replace(/^Name:.*$/m, 'Name:\tm.ihuman.pinyin')
        .replace(/^TracerPid:.*$/m, 'TracerPid:\t0')
        .replace(/^Pid:.*$/m, 'Pid:\t' + tid)
        .replace(/^Tgid:.*$/m, 'Tgid:\t' + mainPid)
        .replace(/^Threads:.*$/m, 'Threads:\t' + cleanN);
      const f1 = FileWriter2.$new(FAKE_TASK + tid + '/status', false); f1.write(s, 0, s.length); f1.close();
      const stat = tid + ' (m.ihuman.pinyin) S ' + mainPid + ' ' + mainPid + ' 0 0 -1 4194528 0 0 0 0 0 0 0 0 0 0 ' + cleanN + ' 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0' + String.fromCharCode(10);
      const f2 = FileWriter2.$new(FAKE_TASK + tid + '/stat', false); f2.write(stat, 0, stat.length); f2.close();
      const f3 = FileWriter2.$new(FAKE_TASK + tid + '/comm', false); const cs = 'm.ihuman.pinyin' + String.fromCharCode(10); f3.write(cs, 0, cs.length); f3.close();
      cnt++;
    }
    send('faketask built: ' + cnt + ' clean tids');
    // converge ALL counts on this single enumeration: the earlier totalT scan
    // may see a different transient-thread count than the build list (24 vs 22
    // happened), which broke the status-vs-enum equality (check 0xdead5014)
    try {
      const patchedSelf = fakeSelf.replace(/^Threads:.*$/m, 'Threads:\t' + cnt);
      const fw3 = FileWriter.$new(sp, false); fw3.write(patchedSelf, 0, patchedSelf.length); fw3.close();
      const patchedStat = mainPid + ' (m.ihuman.pinyin) S ' + mainPid + ' ' + mainPid + ' 0 0 -1 4194528 0 0 0 0 0 0 0 0 0 0 ' + cnt + ' 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0' + String.fromCharCode(10);
      const fw4 = FileWriter.$new(sp2, false); fw4.write(patchedStat, 0, patchedStat.length); fw4.close();
      send('self counts patched to cnt=' + cnt);
    } catch (e: any) { send('self-patch-err ' + e); }
  } catch (e: any) { send('faketask-err ' + e); }

  const FAKE_TASK_PTR = Memory.allocUtf8String(FAKE_TASK);
  const opendirP = Module.getGlobalExportByName('opendir');
  Interceptor.attach(opendirP, {
    onEnter: function (a) {
      try {
        const p = a[0].readCString();
        if (p === '/proc/self/task' || p === '/proc/self/task/') {
          a[0] = FAKE_TASK_PTR;
          send('opendir redirected -> faketask');
        }
      } catch (e) {}
    }
  });
  // openat 精确目录路径也重定向（有些代码直接 open 目录）
  const openatP2 = Module.getGlobalExportByName('openat');
  Interceptor.attach(openatP2, {
    onEnter: function (a) {
      try {
        const p = a[1].readCString();
        if (p === '/proc/self/task' || p === '/proc/self/task/') a[1] = FAKE_TASK_PTR;
      } catch (e) {}
    }
  });
  send('self-mask + faketask-tree armed');
}







function armPropLogger(): void {
  const pg = Module.getGlobalExportByName('__system_property_get');
  if (!pg) { send('no property_get'); return; }
  const FAKE: any = {
    'ro.build.flavor': '',
    'ro.product.model': 'LYA-AL10',
    'ro.hardware': 'kirin980',
    'ro.product.board': 'LYA',
    'ro.board.platform': 'kirin980',
    'gsm.version.baseband': '21C20B379S000C000,21C20B379S000C000'
  };
  const seen: any = {};
  Interceptor.attach(pg, {
    onEnter: function (a) {
      try { this.nm = a[0].readCString(); } catch (e) { this.nm = '?'; }
      this.buf = a[1];
      this.fk = (this.nm in FAKE);
    },
    onLeave: function (r) {
      if (this.fk) {
        try { this.buf.writeUtf8String(FAKE[this.nm]); } catch (e) { try { this.buf.writeCString(FAKE[this.nm]); } catch (e2) {} }
      }
      try {
        let v = '';
        try { v = this.buf.readCString(); } catch (e) {}
        const k = this.nm + '=' + v;
        if (!seen[k]) { seen[k] = 1; send('PROP :: ' + k + (this.fk ? ' [FAKED]' : '')); }
      } catch (e) {}
    }
  });
  send('prop-faker armed (' + Object.keys(FAKE).length + ' props)');
}

function dumpThreads(): void {
  const fopenP = Module.getGlobalExportByName('fopen');
  const fgetsP = Module.getGlobalExportByName('fgets');
  const fcloseP = Module.getGlobalExportByName('fclose');
  const fopen = new NativeFunction(fopenP, 'pointer', ['pointer','pointer']);
  const fgets = new NativeFunction(fgetsP, 'pointer', ['pointer','int','pointer']);
  const fclose = new NativeFunction(fcloseP, 'int', ['pointer']);
  function read(path: string): string {
    const fp = fopen(Memory.allocUtf8String(path), Memory.allocUtf8String('r'));
    if (fp.isNull()) return '<fail>';
    const buf = Memory.alloc(512); let out = '';
    while (!fgets(buf, 512, fp).isNull()) out += buf.readCString();
    fclose(fp);
    return out;
  }
  const st = read('/proc/self/status');
  const tp = st.split('\n').filter(function (l) { return l.indexOf('TracerPid') === 0 || l.indexOf('Name') === 0; });
  send('STATUS ' + tp.join(' ; '));
  const fp = fopen(Memory.allocUtf8String('/proc/self/task'), Memory.allocUtf8String('r'));
  send('task-dir open: ' + fp);
  // 逐线程 comm
  try {
    const opendir = new NativeFunction(Module.getGlobalExportByName('opendir'), 'pointer', ['pointer']);
    const readdir = new NativeFunction(Module.getGlobalExportByName('readdir'), 'pointer', ['pointer']);
    const closedir = new NativeFunction(Module.getGlobalExportByName('closedir'), 'int', ['pointer']);
    const dir = opendir(Memory.allocUtf8String('/proc/self/task'));
    if (!dir.isNull()) {
      // dirent64: skip via readdir64? use readdir (dirent) on bionic64 = readdir64 layout via readdir alias
      let names: string[] = [];
      for (let i = 0; i < 200; i++) {
        const d = readdir(dir);
        if (d.isNull()) break;
        try { names.push(d.add(19).readCString()); } catch (e) {}
      }
      closedir(dir);
      send('TASKS(' + names.length + '): ' + names.join(','));
    }
  } catch (e: any) { send('taskdump-err ' + e); }
}

function armAntiDebug(): void {
  // dlsym 观察 + gDebuggerActive 伪造 + v45 full resolution log
  const dlsymP = Module.getGlobalExportByName('dlsym');
  const fakeZero = Memory.alloc(8);
  fakeZero.writeU64(0);
  let dsN = 0;
  let dsNull = 0;
  let jniEarly = false;
  let earlyJNILogged = false;
  let dsf = 0;
  let dsmiss = 0;
  let dsamb = 0;
  let resolving = false;
  Interceptor.attach(dlsymP, {
    onEnter: function (a) {
      try { this.name = a[1].readCString(); } catch (e) { this.name = '?'; }
      try { this.h = a[0].toInt32(); } catch (e) { this.h = -99999; }
    },
    onLeave: function (r) {
      const n = this.name || '';
      if (n.indexOf('Debugger') >= 0 || n.indexOf('debugger') >= 0 || n.indexOf('gDebugger') >= 0 ||
          n.indexOf('IsDebugger') >= 0 || n.indexOf('Trace') >= 0 || n.indexOf('art::Dbg') >= 0) {
        send('DLSYM-HIT: ' + n + ' -> fake-zero');
        r.replace(fakeZero);
        return;
      }
      // v60: setHongenKAndS is likely called from INSIDE cocos JNI_OnLoad —
      // catch the resolved JNI_OnLoad and install the LuaStack hook at its
      // entry, before its body runs (the 50ms-after-dlopen keyhook is late).
      try {
        if (n === 'JNI_OnLoad' && r && !r.isNull() && !jniEarly) {
          // v61: do NOT consume on the first JNI_OnLoad (that one belongs to
          // an already-loaded lib); arm as soon as the LuaStack export is
          // actually visible (cocos loaded), then stop trying.
          const SYMS = ['_ZN7cocos2d8LuaStack14setHongenKAndSEPKciS2_i',
                        '_ZN7cocos2d8LuaStack18setXXTEAKeyAndSignEPKciS2_i'];
          let lsAddr: any = null;
          let lsMod = '';
          for (let si = 0; si < SYMS.length && !lsAddr; si++) {
            try {
              const mods0 = Process.enumerateModules();
              for (let mi0 = 0; mi0 < mods0.length; mi0++) {
                try {
                  const e0 = mods0[mi0].findExportByName(SYMS[si]);
                  if (e0 && !e0.isNull()) { lsAddr = e0; lsMod = mods0[mi0].name; break; }
                } catch (ee0) {}
              }
            } catch (e0) {}
          }
          if (lsAddr) {
            jniEarly = true;
            Interceptor.attach(lsAddr, {
              onEnter: function (aa) {
                try {
                  const keyLen = aa[1].toInt32();
                  const signLen = aa[3].toInt32();
                  let key = '';
                  let sign = '';
                  let keyHex = '';
                  if (keyLen > 0 && keyLen < 4096) {
                    const kb = aa[0].readByteArray(keyLen);
                    const ku = new Uint8Array(kb);
                    for (let i = 0; i < ku.length; i++) key += String.fromCharCode(ku[i]);
                    keyHex = Array.from(ku).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
                  }
                  if (signLen > 0 && signLen < 4096) {
                    const sb = aa[2].readByteArray(signLen);
                    const su = new Uint8Array(sb);
                    for (let j = 0; j < su.length; j++) sign += String.fromCharCode(su[j]);
                  }
                  send({ ev: 'XXTEA_KEY', via: 'early', key: key, keyLen: keyLen, sign: sign, signLen: signLen, keyHex: keyHex });
                } catch (e2) { send({ ev: 'keyhook_err', via: 'early', e: String(e2) }); }
              }
            });
            send('early-luastack hooked @ ' + lsMod);
          }
          if (!earlyJNILogged) {
            earlyJNILogged = true;
            try {
              Interceptor.attach(r, {
                onEnter: function () { send('JNI_OnLoad enter (early)'); }
              });
            } catch (e) {}
          }
        }
      } catch (e) {}
      try {
        if (r.isNull()) {
          if (dsNull < 80) { dsNull++; send({ ev: 'dsn', n: n, h: this.h }); }
          // v47: RTLD_DEFAULT resolution fails process-wide for symbols that
          // genuinely exist (cocos import batch: strlen/pthread/gl* all NULL
          // with h=0) — fill with the real process-wide address, matching
          // what a real device would return. Skip JNI_OnLoad/Unload: the
          // wrong lib's implementation would mislead ART.
          if (!resolving && n && n !== 'JNI_OnLoad' && n !== 'JNI_OnUnload') {
            // v50: only repair the BROKEN RTLD_DEFAULT batch (h==0).
            // Real-handle lookups (JNI_OnLoad, oat* sections) must keep their
            // natural NULL — feeding them a wrong process-wide address turns
            // expected-NULL probes into wild pointers (crash 0xdfae0eb0).
            if (this.h !== 0) {
              if (dsNull < 80) { /* dsn already logged above */ }
            } else {
            resolving = true;
            let fixed: any = null;
            let how = '';
            try {
              fixed = Module.getGlobalExportByName(n);
              if (fixed && !fixed.isNull()) how = 'g';
              else fixed = null;
            } catch (e) { fixed = null; }
            if (!fixed) {
              try {
                // v56: fill only when EXACTLY ONE module exports the name —
                // an ambiguous first-match can hand the caller a same-named
                // function from the wrong library (corrupts internal state).
                const mods = Process.enumerateModules();
                let hitsN = 0;
                let hitAddr: any = null;
                let hitName = '';
                let conflict = false;
                for (let mi = 0; mi < mods.length; mi++) {
                  try {
                    const e2 = mods[mi].findExportByName(n);
                    if (e2 && !e2.isNull()) {
                      hitsN++;
                      if (!hitAddr) { hitAddr = e2; hitName = mods[mi].name; }
                      else if (!e2.equals(hitAddr)) conflict = true;
                    }
                  } catch (ee) {}
                }
                // duplicate namespace copies share the same address — only a
                // genuine address conflict counts as ambiguity
                if (hitAddr && !conflict) { fixed = hitAddr; how = 'w:' + hitName; }
                else if (conflict && dsamb < 40) { dsamb++; send({ ev: 'dsamb', n: n, m: hitsN }); }
              } catch (e) {}
            }
            if (fixed) {
              r.replace(fixed);
              if (dsf < 300) { dsf++; send({ ev: 'dsf', n: n, how: how }); }
            } else if (dsmiss < 40) {
              dsmiss++;
              send({ ev: 'dsmiss', n: n, h: this.h });
            }
            resolving = false;
            }
          }
        } else if (dsN < 150) {
          dsN++;
          send({ ev: 'ds', n: n, h: this.h });
        }
      } catch (e) {}
    }
  });
  // v46: dlerror strings after failures
  try {
    const dlerrP = Module.getGlobalExportByName('dlerror');
    let deN = 0;
    Interceptor.attach(dlerrP, {
      onLeave: function (ret) {
        try {
          if (!ret.isNull() && deN < 40) {
            deN++;
            send({ ev: 'de', e: ret.readCString() });
          }
        } catch (e) {}
      }
    });
    send('dlerror-hooked');
  } catch (e: any) { send('dlerror-err ' + e); }
  // v45: who walks the link map right before the pc=0 crash?
  try {
    const dip = Module.getGlobalExportByName('dl_iterate_phdr');
    let dipN = 0;
    Interceptor.attach(dip, {
      onEnter: function () { if (dipN < 24) { dipN++; send({ ev: 'dip', i: dipN }); } }
    });
    send('dip-hooked');
  } catch (e: any) { send('dip-err ' + e); }
  // libart 导出的 IsDebuggerActive（若可解析）
  try {
    const ida = Module.getGlobalExportByName('_ZN3art3Dbg16IsDebuggerActiveEv');
    Interceptor.attach(ida, { onLeave: function (r) { r.replace(0); send('IsDebuggerActive->false'); } });
    send('IsDebuggerActive hooked');
  } catch (e: any) { send('IsDebuggerActive unresolvable (ok if inlined)'); }
  send('anti-debug armed');
}

let entered = false;
const mainFn = function (): void {
  entered = true;
  send('bridge-up');
  armDlDeny();
  // v49: pre-load the libs the packer resolves against BEFORE its manual
  // relocation wave — libOpenSLES/libGLESv1_CM otherwise are not loaded yet
  // (their DT_NEEDED only pulls them in with dlopen(cocos), which happens
  // after the wave) and slCreateEngine/AAsset_* come back NULL -> GOT-0 -> pc=0.
  try {
    const dlopenN = new NativeFunction(Module.getGlobalExportByName('dlopen'), 'pointer', ['pointer', 'int']);
    ['libandroid.so', 'libOpenSLES.so', 'libGLESv1_CM.so', 'libGLESv2.so', 'libGLESv3.so'].forEach(function (L) {
      try {
        const h = dlopenN(Memory.allocUtf8String(L), 1 /* RTLD_LAZY */);
        send('preload ' + L + ' ' + (h.isNull() ? 'FAIL' : 'ok'));
      } catch (e) { send('preload-err ' + L + ' ' + e); }
    });
  } catch (e) { send('preload-setup-err ' + e); }
  hookNative();
  armAntiDebug();
  armLogger();
  armPropLogger();
  // armTaskCountMask off in v31: real self/enum keeps status-vs-enum equality
  armStatusRedirect();
  dumpThreads();
  try {
    const B: any = Java.use('android.os.Build');
    B.MODEL.value = 'LYA-AL10'; B.BRAND.value = 'HUAWEI'; B.DEVICE.value = 'HWLYA';
    B.HARDWARE.value = 'kirin980'; B.PRODUCT.value = 'HWLYA';
    B.MANUFACTURER.value = 'HUAWEI'; B.BOARD.value = 'LYA';
    B.FINGERPRINT.value = 'HUAWEI/LYA-AL10/HWLYA:10/HUAWEILYA-AL10/10.1.0.163C00:user/release-keys';
    // NOTE: CPU_ABI/SUPPORTED_ABIS 不动 —— 引导类靠它选 x64 壳
    send('Build spoofed');
  } catch (e: any) { send('Build-err ' + e); }
  try {
    const AMPM = Java.use('android.app.ApplicationPackageManager');
    (AMPM.getPackageInfo.overloads as any[]).forEach(function (ov) {
      ov.implementation = function (this: any) {
        const pi = ov.apply(this, arguments as any);
        try {
          if (String(arguments[0]) === PKG) {
            const Signature = Java.use('android.content.pm.Signature');
            const Base64 = Java.use('android.util.Base64');
            const sig = Signature.$new(Base64.decode(VENDOR_B64, 0));
            pi.signatures.value = Java.array('android.content.pm.Signature', [sig]);
          }
        } catch (e: any) {}
        return pi;
      };
    });
  } catch (e: any) {}
  try {
    const Instr = Java.use('android.app.Instrumentation');
    Instr.callApplicationOnCreate.overload('android.app.Application').implementation = function (app) {
      send('>>> ApplicationOnCreate: ' + app.getClass().getName());
      return this.callApplicationOnCreate(app);
    };
  } catch (e: any) {}
  let tries = 0;
  const iv = setInterval(function () {
    tries++;
    try {
      const SJ: any = Java.use('com.ihuman.lib.security.jni.SecurityJni');
      (SJ.check.overloads as any[]).forEach(function (ov) {
        ov.implementation = function () { send('SJ-BYPASS'); return 1; };
      });
      send('SJ-HOOKED t=' + tries); clearInterval(iv);
    } catch (e: any) { if (tries >= 400) { send('SJ-giveup'); clearInterval(iv); } }
  }, 100);
  // Java 侧调试检测
  try {
    const VMDebug: any = Java.use('dalvik.system.VMDebug');
    VMDebug.isDebuggerConnected.implementation = function () { send('VMDebug-false'); return false; };
  } catch (e: any) { send('VMDebug-skip ' + e); }
  send('hooks-ready');
};
// performNow runs synchronously during script eval (pre-resume) so every
// hook and fake file exists before the shell's gate starts; the deferred
// Java.perform raced the shell's phase-1 reads (real Threads=24 vs enum 22).
try {
  const JX: any = Java as any;
  if (JX.performNow) JX.performNow(mainFn);
  else Java.perform(mainFn);
} catch (e: any) {
  send('perform-err ' + e);
  if (!entered) {
    try { Java.perform(mainFn); } catch (e2: any) { send('perform2-err ' + e2); }
  }
}
