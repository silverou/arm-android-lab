'use strict';
// Universal Java TLS unpinning (for the MITM lane).
setTimeout(function () {
  try {
    Java.perform(function () {
      var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
      var SSLContext = Java.use('javax.net.ssl.SSLContext');
      var TrustAll = Java.registerClass({
        name: 'com.x.TrustAll',
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: function () {},
          checkServerTrusted: function () {},
          getAcceptedIssuers: function () { return []; }
        }
      });
      try {
        var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        init.implementation = function (km, tm, sr) {
          this.init(km, [TrustAll.$new()], sr);
        };
      } catch (e) { send({ ev: 'unpin-init-err', e: String(e) }); }
      try {
        var HV = Java.use('javax.net.ssl.HostnameVerifier');
        var HVC = Java.registerClass({
          name: 'com.x.HostAll',
          implements: [HV],
          methods: { verify: function () { return true; } }
        });
        var HvCls = Java.use('javax.net.ssl.HttpsURLConnection');
        HvCls.setDefaultHostnameVerifier(HVC.$new());
      } catch (e2) { send({ ev: 'unpin-hv-err', e: String(e2) }); }
      send({ ev: 'unpin_ready' });
    });
  } catch (e) { send({ ev: 'unpin_err', e: String(e) }); }
}, 0);
