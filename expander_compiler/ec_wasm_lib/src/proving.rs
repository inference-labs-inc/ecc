use std::io::Cursor;

use arith::Field;
use expander_circuit::RecursiveCircuit;
use expander_transcript::BytesHashTranscript;
use gkr::{BN254ConfigMIMC5Raw, Prover, Verifier};
use gkr_engine::{FieldEngine, GKREngine, GKRScheme, MPIConfig, Proof};
use gkr_hashers::SHA256hasher;
use halo2curves::bn256::Bn256;
use poly_commit::{expander_pcs_init_testing_only, HyperUniKZGPCS};
use serdes::ExpSerde;

use expander_compiler::circuit::layered;

type BN254Config = BN254ConfigMIMC5Raw;
type SIMDField<C> = <<C as GKREngine>::FieldConfig as FieldEngine>::SimdCircuitField;

pub struct BN254ConfigSha2UniKZG;

impl GKREngine for BN254ConfigSha2UniKZG {
    type FieldConfig = <BN254Config as GKREngine>::FieldConfig;
    type MPIConfig = MPIConfig;
    type TranscriptConfig = BytesHashTranscript<SHA256hasher>;
    type PCSConfig = HyperUniKZGPCS<Bn256>;
    const SCHEME: GKRScheme = GKRScheme::Vanilla;
}

type Cfg = BN254ConfigSha2UniKZG;

fn load_circuit(
    circuit_bytes: &[u8],
) -> Result<expander_circuit::Circuit<<Cfg as GKREngine>::FieldConfig>, String> {
    let rc = RecursiveCircuit::<<Cfg as GKREngine>::FieldConfig>::deserialize_from(circuit_bytes)
        .map_err(|e| format!("failed to deserialize circuit: {e}"))?;
    let mut circuit = rc.flatten();
    circuit.pre_process_gkr();
    Ok(circuit)
}

fn dump_proof_and_claimed_v<F: Field>(proof: &Proof, claimed_v: &F) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    proof
        .serialize_into(&mut bytes)
        .map_err(|e| e.to_string())?;
    claimed_v
        .serialize_into(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

fn load_proof_and_claimed_v<F: Field>(bytes: &[u8]) -> Result<(Proof, F), String> {
    let mut cursor = Cursor::new(bytes);
    let proof = Proof::deserialize_from(&mut cursor).map_err(|e| e.to_string())?;
    let claimed_v = F::deserialize_from(&mut cursor).map_err(|e| e.to_string())?;
    Ok((proof, claimed_v))
}

pub fn prove_inner(circuit_bytes: &[u8], witness_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut circuit = load_circuit(circuit_bytes)?;
    let witness = layered::witness::Witness::<BN254Config>::deserialize_from(witness_bytes)
        .map_err(|e| format!("failed to deserialize witness: {e}"))?;

    let (simd_input, simd_public_input) = witness.to_simd::<SIMDField<BN254Config>>();
    circuit.layers[0].input_vals = simd_input;
    circuit.public_input = simd_public_input;
    circuit.evaluate();

    let mpi_config = MPIConfig::prover_new();
    let mut prover = Prover::<Cfg>::new(mpi_config.clone());
    prover.prepare_mem(&circuit);

    let (pcs_params, pcs_proving_key, _, mut pcs_scratch) =
        expander_pcs_init_testing_only::<
            <Cfg as GKREngine>::FieldConfig,
            <Cfg as GKREngine>::PCSConfig,
        >(circuit.log_input_size(), &mpi_config);

    let (claimed_v, proof) = prover.prove(
        &mut circuit,
        &pcs_params,
        &pcs_proving_key,
        &mut pcs_scratch,
    );

    dump_proof_and_claimed_v(&proof, &claimed_v)
}

pub fn verify_inner(
    circuit_bytes: &[u8],
    witness_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<bool, String> {
    let mut circuit = load_circuit(circuit_bytes)?;
    let witness = layered::witness::Witness::<BN254Config>::deserialize_from(witness_bytes)
        .map_err(|e| format!("failed to deserialize witness: {e}"))?;

    let (simd_input, simd_public_input) = witness.to_simd::<SIMDField<BN254Config>>();
    circuit.layers[0].input_vals = simd_input;
    circuit.public_input = simd_public_input.clone();

    let (proof, claimed_v) = load_proof_and_claimed_v::<
        <<Cfg as GKREngine>::FieldConfig as FieldEngine>::ChallengeField,
    >(proof_bytes)?;

    let mpi_config = MPIConfig::verifier_new(1);
    let (pcs_params, _, pcs_verification_key, _) = expander_pcs_init_testing_only::<
        <Cfg as GKREngine>::FieldConfig,
        <Cfg as GKREngine>::PCSConfig,
    >(circuit.log_input_size(), &mpi_config);

    let verifier = Verifier::<Cfg>::new(mpi_config);
    let public_input = circuit.public_input.clone();
    Ok(verifier.verify(
        &mut circuit,
        &public_input,
        &claimed_v,
        &pcs_params,
        &pcs_verification_key,
        &proof,
    ))
}
