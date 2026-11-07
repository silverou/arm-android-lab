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
                    if fl.response:
                        c = fl.response.content
                        out.write('  -> %s len=%s\n' % (fl.response.status_code, len(c) if c else 0))
                except Exception:
                    pass
        except Exception:
            pass
    out.close()
except Exception as e:
    open('flows.txt', 'w').write('FLOWERR ' + str(e) + '\n')
