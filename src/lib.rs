use openssl::bn::{BigNum, BigNumContext};
use sha3::{Digest, Sha3_512};
use std::error::Error;

pub struct SignedData {
    pub data: Vec<u8>,
    pub hash: BigNum,
    pub signature: BigNum,
}

pub struct KeyFactory {
    pub prime1: BigNum,
    pub prime2: BigNum,
    pub generator: BigNum,
    pub hash_function: Sha3_512,
}
pub struct Key {
    private_key: BigNum,
    pub public_key: BigNum,
    pub prime1: BigNum,
    pub prime2: BigNum,
    pub generator: BigNum,
    pub hash_function: Sha3_512,
}

impl KeyFactory {
    pub fn new(prime_size: i32) -> Result<KeyFactory, Box<dyn Error>> {
        let mut prime1 = BigNum::new()?;
        let one = BigNum::from_u32(1)?;
        let two = BigNum::from_u32(2)?;
        prime1.generate_prime(prime_size, true, None, None)?;
        let prime2 = &(&prime1 - &one) / &two;

        //generator ∈ Zprime1 with order prime2, i.e. generator**prime2 = 1 (mod prime1), generator != 1,
        let mut generator = BigNum::new()?;
        let mut temp = BigNum::new()?;
        let mut ctx = BigNumContext::new()?;
        loop {
            prime1.rand_range(&mut temp)?;
            generator.mod_exp(&temp, &two, &prime1, &mut ctx)?;
            if generator != one {
                break;
            }
        }

        Ok(KeyFactory {
            prime1,
            prime2,
            generator: generator,
            hash_function: Sha3_512::new(),
        })
    }

    pub fn generate_keys(&self) -> Result<Key, Box<dyn Error>> {
        let (mut private_key, mut public_key) = (BigNum::new()?, BigNum::new()?);
        let mut ctx = BigNumContext::new()?;

        self.prime2.rand_range(&mut private_key)?;
        let exp = &self.prime2 - &private_key;
        // public_key = generator^exp % prime1
        public_key.mod_exp(&self.generator, &(exp), &self.prime1, &mut ctx)?;

        Ok(Key {
            private_key,
            public_key,
            prime1: self.prime1.to_owned()?,
            prime2: self.prime2.to_owned()?,
            generator: self.generator.to_owned()?,
            hash_function: self.hash_function.to_owned(),
        })
    }
}

impl Key {
    pub fn sign(&self, message: &[u8]) -> Result<SignedData, Box<dyn Error>> {
        let mut ctx = BigNumContext::new()?;
        let mut hash = self.hash_function.clone();
        let (prime1, prime2) = (&self.prime1, &self.prime2);
        let (mut nonce, mut x) = (BigNum::new()?, BigNum::new()?);

        //Pick a random number nonce ∈ (1. ...,prime2)
        prime2.rand_range(&mut nonce)?;
        //compute x := a**nonce(mod p)
        x.mod_exp(&self.generator, &nonce, prime1, &mut ctx)?;
        //Compute e := h(x,message)
        hash.update(x.to_vec());
        hash.update(message);
        let hash = BigNum::from_slice(&hash.finalize())?;

        // Compute signature := nonce + private_key * hash (mod q)
        let mut signature = BigNum::new()?;
        signature.mod_mul(&self.private_key, &hash, prime2, &mut ctx)?;
        let signature_copy = signature.to_owned()?;
        signature.mod_add(&signature_copy, &nonce, prime2, &mut ctx)?;

        Ok(SignedData {
            data: Vec::from(message),
            hash,
            signature,
        })
    }

    pub fn verify(&self, message: &SignedData, pub_key: &BigNum) -> Result<bool, Box<dyn Error>> {
        let mut hash = self.hash_function.to_owned();
        let mut ctx = BigNumContext::new()?;
        let (mut x, mut x1, mut x2) = (BigNum::new()?, BigNum::new()?, BigNum::new()?);
        let (generator, prime1) = (&self.generator, &self.prime1);

        //x = generator**message.signature * pub_key**message.hash (mod prime1)
        x1.mod_exp(generator, &message.signature, prime1, &mut ctx)?;
        x2.mod_exp(pub_key, &message.hash, prime1, &mut ctx)?;
        x.mod_mul(&x1, &x2, prime1, &mut ctx)?;

        // e = h(x,message.data)
        hash.update(x.to_vec());
        hash.update(&message.data);
        let e = hash.finalize();
        let e = BigNum::from_slice(&e)?;

        if e == message.hash {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
