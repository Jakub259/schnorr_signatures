use schnorr::KeyFactory;
use std::error::Error;
#[allow(non_snake_case)]
fn main() -> Result<(), Box<dyn Error>> {
    let key_factory = match KeyFactory::new(256) {
        Ok(item) => item,
        Err(err) => return Err(err),
    };

    let Alice = key_factory.generate_keys()?;
    let Bob = key_factory.generate_keys()?;

    let message = b"Hello World";
    let message_signed = match Alice.sign(message) {
        Ok(sig) => sig,
        Err(err) => panic!("{err}"),
    };

    let result = match Bob.verify(&message_signed, &Alice.public_key) {
        Ok(result) => result,
        Err(err) => panic!("{err}"),
    };
    println!("Messege verified successfully: {result}");

    Ok(())
}
