from py_cryptotp import Cryptotp

otp = Cryptotp(key='xxxxxxxxxxxxxxxx')


new_otp = otp.generate(otp_length=6, otp_duration=2)

print(new_otp)
print(otp.validate(new_otp['raw_otp'], new_otp['hashed_otp']))
