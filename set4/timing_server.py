import binascii
import base64
import tornado.web
import time

import sys
sys.path.append('..')

from set4_utils import *

print '4.31 HMAC-SHA1 with an artificial timing leak'

key = "YELLOW SUBMARINE"
DELAY = .005 # seconds delay between byte compares

def insecure_compare(filename, sig):
    sig = sig.encode('ascii')
    filename = filename.encode('ascii')
    generated_sig = authsha1(key, filename)
    generated_sig = binascii.hexlify(generated_sig)

    if len(generated_sig) != len(sig):
        return False

    print "generated sig", generated_sig
    print 'sig', sig

    for i in xrange(len(generated_sig)):
        if generated_sig[i] != sig[i]:
                return False

        time.sleep(DELAY)

    return True

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write('Nothing to show, move along...')

class TestHandler(tornado.web.RequestHandler):
    def get(self):
        filename = self.get_argument("file", None, True)
        signature = self.get_argument("signature", None, True)

        self.write("filename: " + filename + "<br>")
        self.write("signature " + signature + "<br>")

        if not insecure_compare(filename, signature):
            self.set_status(500)
            self.finish("<html><body>HMAC Check failed</body></html>")
        else:
            self.write("HMAC Check OK")


if __name__ == "__main__":
    application = tornado.web.Application([
        (r"/", MainHandler),
        (r"/test", TestHandler)
    ])
    application.listen(9000)
    tornado.ioloop.IOLoop.current().start()
