import hashlib
import random
import string

def convertToSHA256(x):
    return hashlib.sha256(x).hexdigest()

def generateBytes():
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits
    password = ''.join(random.choice(alphabet) for i in range(8))
    return password, str.encode(password)

def main():
    while 1:
        plain, x = generateBytes()
        checkSum = convertToSHA256(x)
        if(checkSum[0:3] == "000"):
            print("8 byte hex number = ",x)
            print("Generated Checksum = ",checkSum)
            return

if __name__ == "__main__":
    main()