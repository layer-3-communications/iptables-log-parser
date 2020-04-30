import Data.Bytes (Bytes)
import Gauge (bench,whnf,defaultMain)
import Linux.Iptables (decode)

import qualified Data.Bytes as Bytes

-- On my Intel(R) Xeon(R) CPU E3-1505M v5 @ 2.80GHz, this clocks in at
-- around 1.0 microseconds. To be honest, that is not great, but that
-- still puts us at around 1M logs per second. To do better, GHC probably
-- needs to get bytearray literals built in so that we can have the
-- compiler do the hash table lookup rather than doing them in library space.

main :: IO ()
main = defaultMain
  [ bench "A" (whnf decode sampleA)
  ]

sampleA :: Bytes
sampleA = Bytes.fromLatinString $ concat
  [ "Apr 30 08:04:42 thadtop kernel: [50514.038553] IN=wlp2s0 OUT= "
  , "MAC=f4:8c:50:3e:8e:ba:08:02:8e:e7:f6:a4:08:00 SRC=108.177.122.189 "
  , "DST=192.168.1.10 LEN=105 TOS=0x00 PREC=0x20 TTL=119 ID=45030 PROTO=TCP "
  , "SPT=443 DPT=35720 WINDOW=830 RES=0x00 ACK PSH URGP=0"
  ]

