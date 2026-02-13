use wasm_bindgen::prelude::*;

mod proving;

use expander_compiler::circuit::ir::hint_normalized::witness_solver::WitnessSolver;
use expander_compiler::hints::registry::EmptyHintCaller;
use gkr::BN254ConfigMIMC5Raw;
use gkr_engine::FieldEngine;
use serdes::ExpSerde;

type BN254Config = BN254ConfigMIMC5Raw;
type CircuitField<C> = <<C as gkr_engine::GKREngine>::FieldConfig as FieldEngine>::CircuitField;

#[wasm_bindgen]
pub fn solve_witness(
    solver_bytes: &[u8],
    private_inputs: &[u8],
    public_inputs: &[u8],
) -> Result<Vec<u8>, JsError> {
    let solver = WitnessSolver::<BN254Config>::deserialize_from(solver_bytes)
        .map_err(|e| JsError::new(&format!("failed to deserialize solver: {e}")))?;

    let field_size = 32;
    if private_inputs.len() % field_size != 0 {
        return Err(JsError::new(
            "private_inputs length must be a multiple of 32",
        ));
    }
    if public_inputs.len() % field_size != 0 {
        return Err(JsError::new(
            "public_inputs length must be a multiple of 32",
        ));
    }

    let vars: Vec<CircuitField<BN254Config>> = private_inputs
        .chunks_exact(field_size)
        .map(|chunk| {
            CircuitField::<BN254Config>::deserialize_from(chunk)
                .map_err(|e| JsError::new(&format!("failed to deserialize field element: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let public_vars: Vec<CircuitField<BN254Config>> = public_inputs
        .chunks_exact(field_size)
        .map(|chunk| {
            CircuitField::<BN254Config>::deserialize_from(chunk)
                .map_err(|e| JsError::new(&format!("failed to deserialize field element: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let witness = solver
        .solve_witness_from_raw_inputs(vars, public_vars, &EmptyHintCaller)
        .map_err(|e| JsError::new(&format!("witness generation failed: {e}")))?;

    let mut buf = Vec::new();
    witness
        .serialize_into(&mut buf)
        .map_err(|e| JsError::new(&format!("failed to serialize witness: {e}")))?;
    Ok(buf)
}

#[wasm_bindgen]
pub fn prove(circuit_bytes: &[u8], witness_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    proving::prove_inner(circuit_bytes, witness_bytes).map_err(|e| JsError::new(&e))
}

#[wasm_bindgen]
pub fn verify(
    circuit_bytes: &[u8],
    witness_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<bool, JsError> {
    proving::verify_inner(circuit_bytes, witness_bytes, proof_bytes).map_err(|e| JsError::new(&e))
}
