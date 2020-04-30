{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language LambdaCase #-}

module Linux.Iptables
  ( Attribute(..)
  , decode
  ) where

-- Note: I played around with stream fusion in here to see if I could get GHC
-- to generate fast parsing code without having so much boilerplate. I eventually
-- got it to do what I wanted, but it was pretty difficult, and I had to manually
-- fuse two of the passes and get rid of some error checking. I would not recommend
-- using stream fusion for this kind of thing. Also, there is a phase-restricted
-- inline pragma on tokenizeAndParse, and if you remove it, it causes the compiler
-- to hang. I don't know why.

import Data.Bytes.Types (Bytes(Bytes))
import Data.Bytes.Parser (Parser)
import Data.Word (Word16)
import Net.Types (IPv4)
import Data.Bytes.HashMap (Map)
import Net.Protocol (Protocol)
import Data.Word (Word8)

import qualified Data.Bytes as Bytes
import qualified Data.Bytes.HashMap as Map
import qualified Data.Vector.Fusion.Stream.Monadic as Stream
import qualified Data.Bytes.Parser as Parser
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Net.IPv4 as IPv4
import qualified Net.Mac as Mac
import qualified Net.Protocol as Protocol
import qualified Net.Types as Net

data Attribute
  = Source !IPv4
  | Destination !IPv4
  | SourcePort !Word16
  | DestinationPort !Word16
  | Length !Word16
  | TimeToLive !Word8
  | InInterface {-# UNPACK #-} !Bytes
  | OutInterface {-# UNPACK #-} !Bytes
  | Mac !Net.Mac !Net.Mac
    -- ^ For some reason, iptables logs put the source MAC address and the
    -- destination MAC address together. We tease them apart. The first one
    -- is the source, and the second one is the destination.
  | Protocol !Protocol -- ^ @PROTO@
  | Acknowledgement -- ^ @ACK@
  | Synchronize -- ^ @SYN@
  deriving stock (Eq)

data Field
  = FieldSource
  | FieldDestination
  | FieldSourcePort
  | FieldDestinationPort
  | FieldProtocol
  | FieldLength
  | FieldInInterface
  | FieldOutInterface
  | FieldMac

data Tag
  = TagAcknowledgement
  | TagSynchronize

decode :: Bytes -> Maybe [Attribute]
decode b@(Bytes arr _ _) = case Parser.parseBytes parserPrefix b of
  Parser.Failure _ -> Nothing
  Parser.Success (Parser.Slice off len _) ->
    -- These wildcard bangs are here so stop GHC from repeatedly
    -- forcing the hashmaps while parsing the fields.
    let !_ = tags
        !_ = fields
        !_ = Protocol.hashMap
        -- Drop trailing spaces, carriage returns, and newlines. These
        -- often end up at the end of logs.
        !b' = Bytes.dropWhileEnd (\c -> c == 0x0A || c == 0x0D || c == 0x20) (Bytes arr off len)
        -- If you specialize the monad to Identity instead of Just, the
        -- generated code becomes way worse. Not sure why.
     in Stream.foldl' (flip (:)) []
      . Stream.mapMaybe tokenizeAndParse
      . Bytes.splitStream 0x20
      $ b'

fields :: Map Field
fields = Map.fromTrustedList
  [ (Bytes.fromLatinString "SRC", FieldSource)
  , (Bytes.fromLatinString "DST", FieldDestination)
  , (Bytes.fromLatinString "SPT", FieldSourcePort)
  , (Bytes.fromLatinString "DPT", FieldDestinationPort)
  , (Bytes.fromLatinString "PROTO", FieldProtocol)
  , (Bytes.fromLatinString "LEN", FieldLength)
  , (Bytes.fromLatinString "IN", FieldInInterface)
  , (Bytes.fromLatinString "OUT", FieldOutInterface)
  , (Bytes.fromLatinString "MAC", FieldMac)
  ]

tags :: Map Tag
tags = Map.fromTrustedList
  [ (Bytes.fromLatinString "ACK", TagAcknowledgement)
  , (Bytes.fromLatinString "SYN", TagSynchronize)
  ]

tagToAttribute :: Tag -> Attribute
tagToAttribute = \case
  TagAcknowledgement -> Acknowledgement
  TagSynchronize -> Synchronize

fieldToAttribute :: Field -> Bytes -> Maybe Attribute
fieldToAttribute x !b = case x of
  FieldSource -> Source <$> IPv4.decodeUtf8Bytes b
  FieldDestination -> Destination <$> IPv4.decodeUtf8Bytes b
  FieldSourcePort -> decodeWord16 SourcePort b
  FieldDestinationPort -> decodeWord16 DestinationPort b
  FieldMac -> decodeMacPair b
  FieldProtocol -> Protocol <$> Protocol.decode b
  FieldLength -> decodeWord16 Length b
  FieldInInterface -> Just $ InInterface b
  FieldOutInterface -> Just $ OutInterface b

-- If the key is not recognized, we just skip it. Also, if we see
-- a key=val style field and the val is empty, just skip it. This
-- happens with interface names sometimes, and it is better to
-- just not report the field in this situation.
tokenizeAndParse :: Bytes -> Maybe Attribute
{-# inline [0] tokenizeAndParse #-}
tokenizeAndParse atom = case Bytes.split1 0x3D atom of
  Nothing -> case Map.lookup atom tags of
    Nothing -> Nothing
    Just tag -> Just (tagToAttribute tag)
  Just (key, b@(Bytes _ _ len)) -> case len of
    0 -> Nothing
    _ -> case Map.lookup key fields of
      Nothing -> Nothing
      Just field -> fieldToAttribute field b

parserPrefix :: Parser () s ()
parserPrefix = do
  skipInitialDate
  Latin.skipTrailedBy () '['
  Latin.skipDigits1 ()
  Latin.char () '.'
  Latin.skipDigits1 ()
  Latin.char () ']'

-- The initial datetime is formatted like this: Dec 6 10:04:50.
-- It is always missing the year. This consumes a trailing space.
skipInitialDate :: Parser () s ()
skipInitialDate = do
  match isUpper
  match isLower
  match isLower
  Latin.char () ' '
  Latin.skipDigits1 ()
  Latin.char () ' '
  match isDigit
  match isDigit
  Latin.char () ':'
  match isDigit
  match isDigit
  Latin.char () ':'
  match isDigit
  match isDigit
  Latin.char () ' '

isUpper :: Char -> Bool
isUpper c = c >= 'A' && c <= 'Z'

isLower :: Char -> Bool
isLower c = c >= 'a' && c <= 'z'

isDigit :: Char -> Bool
isDigit c = c >= '0' && c <= '9'

match :: (Char -> Bool) -> Parser () s ()
{-# inline match #-}
match p = do
  c <- Latin.any ()
  case p c of
    True -> pure ()
    False -> Parser.fail ()

decodeWord16 :: (Word16 -> x) -> Bytes -> Maybe x
decodeWord16 f b = Parser.parseBytesMaybe
  ( do w <- Latin.decWord16 ()
       pure (f w)
  ) b

decodeMacPair :: Bytes -> Maybe Attribute
decodeMacPair !b = Parser.parseBytesMaybe
  ( do src <- Mac.parserUtf8Bytes ()
       Latin.char () ':'
       dst <- Mac.parserUtf8Bytes ()
       Latin.char () ':'
       _ <- Latin.hexNibble ()
       _ <- Latin.hexNibble ()
       Latin.char () ':'
       _ <- Latin.hexNibble ()
       _ <- Latin.hexNibble ()
       pure (Mac src dst)
  ) b
