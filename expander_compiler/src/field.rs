pub use arith::{Field as FieldArith, Fr as BN254Fr};
#[cfg(feature = "babybear")]
use babybear::{BabyBear, BabyBearx16};
#[cfg(feature = "gf2")]
pub use gf2::{GF2x8, GF2};
#[cfg(feature = "goldilocks")]
pub use goldilocks::{Goldilocks, Goldilocksx8};
#[cfg(feature = "mersenne31")]
pub use mersenne31::{M31x16, M31};
use serdes::ExpSerde;

pub trait Field: FieldArith + ExpSerde {
    fn optimistic_inv(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else if *self == Self::ONE {
            Some(Self::ONE)
        } else {
            self.inv()
        }
    }
}

impl Field for BN254Fr {}
#[cfg(feature = "gf2")]
impl Field for GF2 {}
#[cfg(feature = "mersenne31")]
impl Field for M31 {}
#[cfg(feature = "goldilocks")]
impl Field for Goldilocks {}
#[cfg(feature = "babybear")]
impl Field for BabyBear {}

pub trait FieldRaw: FieldArith {}

impl FieldRaw for BN254Fr {}
#[cfg(feature = "gf2")]
impl FieldRaw for GF2 {}
#[cfg(feature = "mersenne31")]
impl FieldRaw for M31 {}
#[cfg(feature = "mersenne31")]
impl FieldRaw for M31x16 {}
#[cfg(feature = "gf2")]
impl FieldRaw for GF2x8 {}
#[cfg(feature = "goldilocks")]
impl FieldRaw for Goldilocks {}
#[cfg(feature = "goldilocks")]
impl FieldRaw for Goldilocksx8 {}
#[cfg(feature = "babybear")]
impl FieldRaw for BabyBear {}
#[cfg(feature = "babybear")]
impl FieldRaw for BabyBearx16 {}
