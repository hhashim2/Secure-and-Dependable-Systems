--
-- simple RSA implementation written during the SADS class on 2020-03-26
-- 

import System.Random
import Text.Printf
import Data.Char

data Key = Key Integer Integer deriving (Show)
data KeyPair = KeyPair Key Key deriving (Show)

isPrime :: Integer -> Bool
isPrime p = null [ x | x <- 2:[3,5..r], p `mod` x == 0]
  where r = (floor . sqrt . fromIntegral) p

randomInteger :: Integer -> Integer -> IO Integer
randomInteger m n = randomRIO (m, n)

randomPrime :: Integer -> Integer -> IO Integer
randomPrime m n =
  do
    x <- randomInteger m n
    if isPrime x
      then return x
      else randomPrime m n

phi p q = (p-1) * (q-1)

pubExponent :: Integer -> Integer -> IO Integer
pubExponent p q =
  do
    e <- randomInteger 2 ((phi p q) - 1)
    if gcd e (phi p q) == 1
      then return e
      else pubExponent p q

--for a b calculate d and s and t such that d=gcd(a,b) and d = s*a + t*b
egcd :: Integer -> Integer -> (Integer, Integer, Integer)
egcd a 0 = (abs a, signum a, 0)
egcd a b = (d, t, s - (a `div` b) * t)
  where (d, s, t) = egcd b (a `mod` b)

priExponent :: Integer -> Integer -> Integer -> IO Integer
priExponent e p q
  | d /= 1    = error "no inverse for e in Zp"
  | s <  0    = return (s + phi p q)
  | otherwise = return s
  where (d, s, t) = egcd e (phi p q)

genKeyPair :: Integer -> Integer -> IO KeyPair
genKeyPair n m =
  do
    p <- randomPrime n m
    q <- randomPrime n m
    e <- pubExponent p q
    d <- priExponent e p q
    return (KeyPair (Key e (p * q)) (Key d (p * q)))

encNum :: Integer -> Key -> Integer
encNum m (Key e n) = (m^e) `mod` n

enc :: [Integer] -> Key -> [Integer]
enc ms k = map (`encNum` k) ms

decNum :: Integer -> Key -> Integer
decNum c (Key d n) = (c^d) `mod` n

dec :: [Integer] -> Key -> [Integer]
dec cs k = map (`decNum` k) cs

strToNum :: String -> [Integer]
strToNum = map (fromIntegral . ord)

numToStr :: [Integer] -> String
numToStr = map (chr . fromIntegral)

demo s n m =
  do
    (KeyPair ke kd) <- genKeyPair n m
    printf "ke:\t\t%s\n"      $ show ke
    printf "kd:\t\t%s\n"      $ show kd
    printf "input:\t\t%s\n"   $ show s
    printf "encrypted:\t%s\n" $ show (enc (strToNum s) ke)
    printf "decrypted:\t%s\n" $ show (dec (enc (strToNum s) ke) kd)
    printf "output:\t\t%s\n"  $ show (numToStr (dec (enc (strToNum s) ke) kd))

main =
  do
    demo "Jacobs University" 100 1000
    demo "Inspiration is a place." 100 1000
