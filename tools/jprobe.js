'use strict';
/* Java-side probe: enumerate SDK classes and methods related to device id. */
function emit(o) { send(o); }
var done = false;
var tries = 0;

function probe() {
  tries++;
  if (done) return;
  try {
    if (typeof Java === 'undefined') {
      if (tries % 4 === 1) emit({ ev: 'jnope', t: tries });
      return;
    }
    Java.perform(function () {
      var hits = [];
      Java.enumerateLoadedClasses({
        onMatch: function (n) {
          if (/ihuman|hongen|pinyin|Hpyr/i.test(n) && hits.length < 400) hits.push(n);
        },
        onComplete: function () {
          emit({ ev: 'jcls', n: hits });
          var found = [];
          for (var i = 0; i < hits.length; i++) {
            var cn = hits[i];
            if (!/device|sdk|util|common/i.test(cn)) continue;
            try {
              var C = Java.use(cn);
              var names = [];
              var ms = C.class.getDeclaredMethods();
              for (var j = 0; j < ms.length && j < 200; j++) {
                var mn = ms[j].getName();
                if (/device|Device|uid/i.test(mn)) names.push(mn);
              }
              if (names.length) {
                found.push(cn + ' :: ' + names.join(','));
                emit({ ev: 'jdevm', cls: cn, ms: names });
              }
            } catch (e2) {}
          }
          emit({ ev: 'jdev_done', n: found.length });
          done = true;
        }
      });
    });
  } catch (e) {
    emit({ ev: 'jerr', e: String(e) });
  }
}

setInterval(probe, 6000);
setTimeout(probe, 3000);
