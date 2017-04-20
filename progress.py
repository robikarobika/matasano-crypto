import progressbar
import time

l = [i for i in xrange(10)]

for i in progressbar.ProgressBar(widgets=[progressbar.Counter(), ' ', progressbar.Percentage(), ' ', progressbar.Bar(), ' ', progressbar.ETA()])(l):
    time.sleep(1)
