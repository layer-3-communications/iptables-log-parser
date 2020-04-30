{-# language PatternSynonyms #-}

import Data.Bytes (Bytes)
import Linux.Iptables (Attribute(..),decode)
import Net.Protocol (pattern Tcp)

import qualified Data.Bytes as Bytes
import qualified Net.IPv4 as IPv4
import qualified Net.Mac as Mac

main :: IO ()
main = do
  putStrLn "Starting"
  testA
  putStrLn "Finished"

testA :: IO ()
testA = case decode sampleA of
  Nothing -> fail "Could not decode A"
  Just attrs
    | notElem (DestinationPort 35720) attrs -> fail "bad destination port"
    | notElem (SourcePort 443) attrs -> fail "bad source port"
    | notElem (Destination (IPv4.fromOctets 192 168 1 10)) attrs -> fail "bad dest ip"
    | notElem (Source (IPv4.fromOctets 108 177 122 189)) attrs -> fail "bad source ip"
    | notElem (Protocol Tcp) attrs -> fail "bad protocol"
    | notElem (InInterface (Bytes.fromLatinString "wlp2s0")) attrs -> fail "bad in interface"
    | notElem (Mac (Mac.mac 0xf48c503e8eba) (Mac.mac 0x08028ee7f6a4)) attrs -> fail "bad MAC addresses"
    | otherwise -> pure ()

sampleA :: Bytes
sampleA = Bytes.fromLatinString $ concat
  [ "Apr 30 08:04:42 thadtop kernel: [50514.038553] IN=wlp2s0 OUT= "
  , "MAC=f4:8c:50:3e:8e:ba:08:02:8e:e7:f6:a4:08:00 SRC=108.177.122.189 "
  , "DST=192.168.1.10 LEN=105 TOS=0x00 PREC=0x20 TTL=119 ID=45030 PROTO=TCP "
  , "SPT=443 DPT=35720 WINDOW=830 RES=0x00 ACK PSH URGP=0"
  ]

