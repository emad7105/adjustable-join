# Adjustable Join
This adjustable join scheme has been insipred by the paper CryptDB. However, the implementation uses slightly different constructions.

# Construction

Here is the highlevel overview of the scheme:  

(prfKey, sk) &larr; **KeyGens**()  

C &larr; **Encrypt**(prfKey, sk, data):
- P &larr; HashToCurve(HMAC(prfKey, data))
- C &larr; (sk)P

delta &larr; **DeltaToken**(oldSk, newSk):
- Compute 1/oldSk &larr; inverse(oldSk)
- Compute delta &larr; (1/oldSk)(newSk)

C' &larr; **Adjust**(C, delta):
- Compute C' &larr; (delta)(C) = (newSK/oldSk)(oldSk)P


# Disclaimer
This scheme should only be used for research purposes. This repository is neither audited nor the construction is fully sanity-checked. 
