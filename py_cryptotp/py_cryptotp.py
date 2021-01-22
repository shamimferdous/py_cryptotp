from random import randint
from datetime import datetime, timedelta
from base64 import b64encode, b64decode
from Crypto.Cipher import AES


# creating crypto object
class Cryptotp:
    """
    key: str
        16 digit secret key used for hashing the OTP. Keep it safe
    """

    key: bytes

    def __init__(self, key):
        self.key = bytes(key, 'utf-8')

        # creating new crypto object
        self.crypto = AES.new(self.key, AES.MODE_OFB)

    def generate(self, otp_length: int, otp_duration: int):
        """
        this method takes "otp_length" and "otp_duration" as params and returns a dict with the "raw_otp" and "hashed_otp"

        raw_otp - a random number of given length \n
        hashed_otp - a hashed string which underneth contains the raw_otp and the expiration_time which equals to given duration
        """

        # generating otp by calling random_generator method
        raw_otp = self.__otp_generator(otp_length)

        # converting raw_otp and expiration timestamp into a string separeted by '?'
        otp_w_time_signature = str(raw_otp) + "?" + \
            str(datetime.now() + timedelta(minutes=otp_duration))

        # hasing the string
        hashed_otp_in_bytes = self.crypto.encrypt(
            bytes(otp_w_time_signature, 'utf-8'))

        hashed_otp = b64encode(self.crypto.iv).decode() + \
            "?" + b64encode(hashed_otp_in_bytes).decode()

        # returning otp dict
        otp = {
            "raw_otp": raw_otp,
            "hashed_otp": hashed_otp
        }

        return otp

    def validate(self, user_given_otp, hashed_otp):
        """
        This method takes the user_given_otp and hashed_otp string as parameter and returns a boolean 
        It destructs, decrypts and retrives the actual otp and expiration time
        Then it checks if the user given otp matches with actual otp and the expiration time is in future
        """

        # destructuring the hashed_otp
        hashed_otp_object = hashed_otp.split('?')
        iv = b64decode(hashed_otp_object[0])
        hash_string = b64decode(hashed_otp_object[1])

        # decrypting the hashed otp
        de_crypto = AES.new(self.key, AES.MODE_OFB, iv=iv)
        raw_otp_string = de_crypto.decrypt(hash_string).decode()
        raw_otp_object = raw_otp_string.split('?')

        # converting expiration time string to datetime
        expiration_time = datetime.strptime(
            raw_otp_object[1], '%Y-%m-%d %H:%M:%S.%f')

        # validating input
        if datetime.now() <= expiration_time and int(user_given_otp) == int(raw_otp_object[0]):
            return True

        return False

    # random n digit number genetor
    def __otp_generator(self, length):
        start_range = 10**(length - 1)
        end_range = (10**length) - 1

        return randint(start_range, end_range)
