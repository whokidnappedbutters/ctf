#!/usr/bin/python

import sys

sys.path.append('../')

from util import *

N = 81546073902331759271984999004451939555402085006705656828495536906802924215055062358675944026785619015267809774867163668490714884157533291262435378747443005227619394842923633601610550982321457446416213545088054898767148483676379966942027388615616321652290989027944696127478611206798587697949222663092494873481
lsbfile = 'bytes.txt'

s = lsb_attack (lsbfile, N)
print("Decrypted string: {0}".format(s))
