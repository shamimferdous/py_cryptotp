py_cryptotp
===========

py_cryptotp is a package that let's you generate and handle OTP or 2 step verifications easily and securely without using any DATABASES. 

It's a very common practice to use databases while handling otp verifications; primarily to storing and later retrieving it to match with user input. But this shouldn't be the way of handling it. Otp is just a temporary data which doesn't belong to the database. Not to mention database operations are comparatively slow and costly.

py_cryptotp eliminates this problem by using cryptography underneath. `This package simply uses the built-in python hashlib and hmac module and doesn't rely on any other dependencies. ` 



# Installation and Usage


```
$ pip install py-cryptotp
```

Once the installation is done import py_cryptotp and create a new object:

```
from py_cryptotp import Cryptotp

otp_handler = Cryptotp(key='YourSecretKeyHere') # keep this secret key secure
```

Then use the `generate` method to generate a new otp. Here `otp_length` is the length of the otp and `otp_duration` is the expiration time of the otp in **minutes**
```
raw_otp, hashed_otp = otp_handler.generate(otp_length=6, otp_duration=2)
# raw_otp - 123456
# hashed_otp - a45256bbeb6d90aad762ce9552e458064aa85054a.1611669734
``` 
It will return the `raw_otp` and `hashed_otp`. Send the `raw_otp` to user via SMS, Email or anyway you choose and send the `hashed_otp` to the client. If your client is [React](https://reactjs.org) or [Vue](https://vuejs.org) you can just store it in a state variable. Or you can also use `Local Storage`, `Session Storage` etc to store it. As it's completely hashed and irreversible it doesn't matter where you're storing it.

Then when the user gets the otp and enters it to client send back the `hashed_otp` with the user given otp and use the `validate` method:
```
if otp_handler.validate(user_give_otp, hashed_otp):
        # do further operations accordingly 
```
The `validate` method gives back a `boolean` value. If the user given otp is correct and expiration time is in future it returns `True` otherwise `False`

Here's a [sample django rest framework application](https://github.com/shamimferdous/py_cryptotp-djangorf-demo) that demonstrate the whole package properly.
