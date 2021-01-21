from py_cryptotp import Cryptotp

otp = Cryptotp(6, 5, 'xxxxxxxxxxxxxxxx')
new_otp = otp.generate()
print(new_otp)
print(otp.validate(new_otp['raw_otp'], new_otp['hashed_otp']))
