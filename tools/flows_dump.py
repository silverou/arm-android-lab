import sys
try:
    from mitmproxy import io as mio
    out = open('flows.txt', 'w', encoding='utf-8', errors='replace')
    with open('/tmp/flows.mitm', 'rb') as f:
        fr = mio.FlowReader(f)
        try:
            for fl in fr.stream():
                try:
                    out.write('%s %s\n' % (fl.request.method, fl.request.pretty_url))
                    for k, v in fl.request.headers.items():
                        out.write('  > %s: %s\n' % (k, v))
                    if fl.request.content:
                        try:
                            b = fl.request.content.decode('utf-8', 'replace')
                        except Exception:
                            b = repr(fl.request.content)
                        out.write('  BODY: %s\n' % b[:3000])
                    if fl.response:
                        out.write('  -> %s len=%s\n' % (fl.response.status_code, len(fl.response.content or b'')))
                        for k, v in fl.response.headers.items():
                            if k.lower() in ('content-encoding', 'content-type', 'transfer-encoding'):
                                continue
                            out.write('  < %s: %s\n' % (k, v))
                        try:
                            rb = fl.response.content.decode('utf-8', 'replace')
                            out.write('  RBODY: %s\n' % rb[:3000])
                        except Exception:
                            pass
                    out.write('\n')
                except Exception as e:
                    out.write('  FLOWPART_ERR %s\n' % e)
        except Exception as e:
            out.write('FLOWSTREAM_ERR %s\n' % e)
    out.close()
except Exception as e:
    open('flows.txt', 'w').write('FLOWERR ' + str(e) + '\n')
