
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

  function read(path: string): string {
    const fp = fopenC(Memory.allocUtf8String(path), Memory.allocUtf8String('r'));
    if (fp.isNull()) return '';
    const buf = Memory.alloc(8192); let out = '';
    while (!fgetsC(buf, 8192, fp).isNull()) out += buf.readCString();
    fcloseC(fp);
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
    send('self-pin V=' + pinV + ' slen=' + pinStatus.length + ' statlen=' + pinStat.length);
  }
  pinNow();

  const mainPid = Process.id.toString();
  const memfdCreate = new NativeFunction(Module.getGlobalExportByName('memfd_create'), 'int', ['pointer','int']);
  const writeC = new NativeFunction(Module.getGlobalExportByName('write'), 'long', ['int', 'pointer', 'long']);
  const closeC = new NativeFunction(Module.getGlobalExportByName('close'), 'int', ['int']);

  // v37 keeps the v31 real-enum design; content now derives from the pin.
  function contentFor(tid: string, kind: string): string {
    if (kind === 'comm') return 'm.ihuman.pinyin\n';
    if (!pinned) return '';
    if (kind === 'status') {
      return pinStatus
        .replace(/^Pid:.*$/m, 'Pid:\t' + tid)
        .replace(/^Tgid:.*$/m, 'Tgid:\t' + mainPid);
    }
    return tid + ' (m.ihuman.pinyin) S ' + mainPid + ' ' + mainPid +
      ' 0 0 -1 4194528 0 0 0 0 0 0 0 0 0 0 ' + pinV +
      ' 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0' + String.fromCharCode(10);
  }
  const memfdOf = (content: string, name: string): number => {
    if (!content) return -1;
    const fd = memfdCreate(Memory.allocUtf8String(name), 0);
    if (fd < 0) { send('memfd-fail ' + name); return -1; }
    writeC(fd, Memory.allocUtf8String(content), content.length);
    return fd;
  };
  const redirectTo = (a: any, idx: number, tid: string, kind: string, st: any): void => {
    const fd = memfdOf(contentFor(tid, kind), 'x' + tid + kind.charAt(0));
    if (fd >= 0) {
      a[idx] = Memory.allocUtf8String('/proc/self/fd/' + fd);
      st.mfd = fd;
      if (dR < 40) { dR++; send('RED-x ' + tid + ' ' + kind + ' fd' + fd); }
    }
  };
  const redirectToSelf = (a: any, idx: number, kind: string, st: any): void => {
    if (!pinned) return;
    const content = kind === 'status' ? pinStatus : pinStat;
    const fd = memfdOf(content, 'self' + kind.charAt(0));
    if (fd >= 0) {
      a[idx] = Memory.allocUtf8String('/proc/self/fd/' + fd);
      st.mfd = fd;
      if (dR < 40) { dR++; send('RED-self ' + kind + ' fd' + fd); }
    }
  };

  const openatP = Module.getGlobalExportByName('openat');
  Interceptor.attach(openatP, {
    onEnter: function (a) {
      this.mfd = -1;
      try {
        const p = a[1].readCString();
        if (dA < 25) { dA++; send('AEN ' + p); }
        if (p === '/proc/self/status') redirectToSelf(a, 1, 'status', this);
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
      try {
        const p = a[0].readCString();
        if (dF < 25) { dF++; send('FEN ' + p); }
        if (p === '/proc/self/status') redirectToSelf(a, 0, 'status', this);
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
      try {
        const p = a[0].readCString();
        if (dO < 25) { dO++; send('OEN ' + p); }
        if (p === '/proc/self/status') redirectToSelf(a, 0, 'status', this);
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
  send('v38 self-pin + per-tid redirect armed (mainPid=' + mainPid + ')');
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
  // dlsym 观察 + gDebuggerActive 伪造
  const dlsymP = Module.getGlobalExportByName('dlsym');
  const fakeZero = Memory.alloc(8);
  fakeZero.writeU64(0);
  Interceptor.attach(dlsymP, {
    onEnter: function (a) {
      try { this.name = a[1].readCString(); } catch (e) { this.name = '?'; }
    },
    onLeave: function (r) {
      const n = this.name || '';
      if (n.indexOf('Debugger') >= 0 || n.indexOf('debugger') >= 0 || n.indexOf('gDebugger') >= 0 ||
          n.indexOf('IsDebugger') >= 0 || n.indexOf('Trace') >= 0 || n.indexOf('art::Dbg') >= 0) {
        send('DLSYM-HIT: ' + n + ' -> fake-zero');
        r.replace(fakeZero);
      }
    }
  });
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
