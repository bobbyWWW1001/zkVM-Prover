use sp1_sdk::{include_elf, ProverClient, SP1Stdin, HashableKey};
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};

const ELF: &[u8] = include_elf!("prime");

#[derive(Debug)]
struct ProofData {
    proof: String,
    public_inputs: String,
    vkey_hash: String,
}

fn main() {
    let test_number = 17u32;

    let mut stdin = SP1Stdin::new();
    stdin.write(&test_number);

    let client = ProverClient::from_env();
    
    println!("Starting proof generation...");
    
    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, &stdin).groth16().run().expect("Proof generation failed");

    println!("Proof generation completed!");
    
    let fixture = ProofData {
        proof: hex::encode(proof.bytes()),
        public_inputs: hex::encode(proof.public_values),
        vkey_hash: vk.bytes32(),
    };
    
    println!("Proof data: {:?}", fixture);
    
    let proof_bytes = hex::decode(fixture.proof).expect("Invalid proof data");
    let public_inputs_bytes = hex::decode(fixture.public_inputs).expect("Invalid public inputs");
    let vkey_hash_str = fixture.vkey_hash.as_str();
    
    let result = Groth16Verifier::verify(
        &proof_bytes,
        &public_inputs_bytes,
        vkey_hash_str,
        *GROTH16_VK_BYTES
    ).is_ok();
    
    println!("Verification result: {}", if result {
        "The number is indeed prime!"
    } else {
        "The number is not prime!"
    });
}
