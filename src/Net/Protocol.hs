{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language MagicHash #-}
{-# language PatternSynonyms #-}
{-# language TypeApplications #-}

module Net.Protocol
  ( -- * Types
    Protocol(..)
    -- * Decode
  , decode
    -- * Decode
  , hashMap
    -- * Patterns
  , pattern Tcp
  , pattern Igp
  , pattern Udp
  , pattern Sctp
  , pattern Icmp
  , pattern Igmp
  ) where

import Data.Bytes (Bytes)
import Data.Bytes.HashMap.Word (Map)
import Data.Char (toLower,toUpper)
import Data.Word (Word8)
import GHC.Base (unpackCString#)
import GHC.Exts (Addr#)

import qualified Data.Bytes as Bytes
import qualified Data.Bytes.HashMap.Word as Map

newtype Protocol = Protocol Word8
  deriving newtype (Eq)

pattern Tcp :: Protocol
pattern Tcp = Protocol 6

pattern Igp :: Protocol
pattern Igp = Protocol 9

pattern Udp :: Protocol
pattern Udp = Protocol 17

pattern Sctp :: Protocol
pattern Sctp = Protocol 132

pattern Icmp :: Protocol
pattern Icmp = Protocol 1

pattern Igmp :: Protocol
pattern Igmp = Protocol 2

decode :: Bytes -> Maybe Protocol
decode b = case Map.lookup b hashMap of
  Nothing -> Nothing
  Just w -> Just (Protocol (fromIntegral w))

-- | Resolves protocol names to IANA numbers. 
hashMap :: Map
hashMap = Map.fromTrustedList $ do
  RawPair key val <- rawProtocolPairs
  let val' = fromIntegral @Word8 @Word val
      str = unpackCString# key
      upper = Bytes.fromLatinString (map toUpper str)
      lower = Bytes.fromLatinString (map toLower str)
  [(upper, val'), (lower, val'), (Bytes.fromLatinString str, val')]

data RawPair = RawPair Addr# !Word8

rawProtocolPairs :: [RawPair]
rawProtocolPairs =
  [ RawPair "HOPOPT"# 0
  , RawPair "ICMP"# 1
  , RawPair "IGMP"# 2
  , RawPair "GGP"# 3
  , RawPair "IPv4"# 4
  , RawPair "ST"# 5
  , RawPair "TCP"# 6
  , RawPair "CBT"# 7
  , RawPair "EGP"# 8
  , RawPair "IGP"# 9
  , RawPair "BBN-RCC-MON"# 10
  , RawPair "NVP-II"# 11
  , RawPair "PUP"# 12
  , RawPair "EMCON"# 14
  , RawPair "XNET"# 15
  , RawPair "CHAOS"# 16
  , RawPair "UDP"# 17
  , RawPair "MUX"# 18
  , RawPair "DCN-MEAS"# 19
  , RawPair "HMP"# 20
  , RawPair "PRM"# 21
  , RawPair "XNS-IDP"# 22
  , RawPair "TRUNK-1"# 23
  , RawPair "TRUNK-2"# 24
  , RawPair "LEAF-1"# 25
  , RawPair "LEAF-2"# 26
  , RawPair "RDP"# 27
  , RawPair "IRTP"# 28
  , RawPair "ISO-TP4"# 29
  , RawPair "NETBLT"# 30
  , RawPair "MFE-NSP"# 31
  , RawPair "MERIT-INP"# 32
  , RawPair "DCCP"# 33
  , RawPair "3PC"# 34
  , RawPair "IDPR"# 35
  , RawPair "XTP"# 36
  , RawPair "DDP"# 37
  , RawPair "IDPR-CMTP"# 38
  , RawPair "TP++"# 39
  , RawPair "IL"# 40
  , RawPair "IPv6"# 41
  , RawPair "SDRP"# 42
  , RawPair "IPv6-Route"# 43
  , RawPair "IPv6-Frag"# 44
  , RawPair "IDRP"# 45
  , RawPair "RSVP"# 46
  , RawPair "GRE"# 47
  , RawPair "DSR"# 48
  , RawPair "BNA"# 49
  , RawPair "ESP"# 50
  , RawPair "AH"# 51
  , RawPair "I-NLSP"# 52
  , RawPair "SWIPE"# 53
  , RawPair "NARP"# 54
  , RawPair "MOBILE"# 55
  , RawPair "TLSP"# 56
  , RawPair "SKIP"# 57
  , RawPair "IPv6-ICMP"# 58
  , RawPair "IPv6-NoNxt"# 59
  , RawPair "IPv6-Opts"# 60
  , RawPair "CFTP"# 62
  , RawPair "SAT-EXPAK"# 64
  , RawPair "KRYPTOLAN"# 65
  , RawPair "RVD"# 66
  , RawPair "IPPC"# 67
  , RawPair "SAT-MON"# 69
  , RawPair "VISA"# 70
  , RawPair "IPCV"# 71
  , RawPair "CPNX"# 72
  , RawPair "CPHB"# 73
  , RawPair "WSN"# 74
  , RawPair "PVP"# 75
  , RawPair "BR-SAT-MON"# 76
  , RawPair "SUN-ND"# 77
  , RawPair "WB-MON"# 78
  , RawPair "WB-EXPAK"# 79
  , RawPair "ISO-IP"# 80
  , RawPair "VMTP"# 81
  , RawPair "SECURE-VMTP"# 82
  , RawPair "VINES"# 83
  , RawPair "TTP"# 84
  , RawPair "IPTM"# 84
  , RawPair "NSFNET-IGP"# 85
  , RawPair "DGP"# 86
  , RawPair "TCF"# 87
  , RawPair "EIGRP"# 88
  , RawPair "OSPFIGP"# 89
  , RawPair "Sprite-RPC"# 90
  , RawPair "LARP"# 91
  , RawPair "MTP"# 92
  , RawPair "AX.25"# 93
  , RawPair "IPIP"# 94
  , RawPair "MICP"# 95
  , RawPair "SCC-SP"# 96
  , RawPair "ETHERIP"# 97
  , RawPair "ENCAP"# 98
  , RawPair "GMTP"# 100
  , RawPair "IFMP"# 101
  , RawPair "PNNI"# 102
  , RawPair "PIM"# 103
  , RawPair "ARIS"# 104
  , RawPair "SCPS"# 105
  , RawPair "QNX"# 106
  , RawPair "A/N"# 107
  , RawPair "IPComp"# 108
  , RawPair "SNP"# 109
  , RawPair "Compaq-Peer"# 110
  , RawPair "IPX-in-IP"# 111
  , RawPair "VRRP"# 112
  , RawPair "PGM"# 113
  , RawPair "L2TP"# 115
  , RawPair "DDX"# 116
  , RawPair "IATP"# 117
  , RawPair "STP"# 118
  , RawPair "SRP"# 119
  , RawPair "UTI"# 120
  , RawPair "SMP"# 121
  , RawPair "SM"# 122
  , RawPair "PTP"# 123
  , RawPair "ISIS over IPv4"# 124
  , RawPair "FIRE"# 125
  , RawPair "CRTP"# 126
  , RawPair "CRUDP"# 127
  , RawPair "SSCOPMCE"# 128
  , RawPair "IPLT"# 129
  , RawPair "SPS"# 130
  , RawPair "PIPE"# 131
  , RawPair "SCTP"# 132
  , RawPair "FC"# 133
  , RawPair "RSVP-E2E-IGNORE"# 134
  , RawPair "Mobility Header"# 135
  , RawPair "UDPLite"# 136
  , RawPair "MPLS-in-IP"# 137
  , RawPair "manet"# 138
  , RawPair "HIP"# 139
  , RawPair "Shim6"# 140
  , RawPair "WESP"# 141
  , RawPair "ROHC"# 142
  , RawPair "Ethernet"# 143
  ]
