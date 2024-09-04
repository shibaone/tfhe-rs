use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::prelude::{
    CiphertextModulus, Container, DecompositionBaseLog, DecompositionLevelCount, LweSize,
    SeededLweKeyswitchKey, UnsignedInteger,
};

#[derive(Version)]
pub struct SeededLweKeyswitchKeyV0<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_lwe_size: LweSize,
    compression_seed: CompressionSeed,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> Upgrade<SeededLweKeyswitchKey<C>>
    for SeededLweKeyswitchKeyV0<C>
{
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<SeededLweKeyswitchKey<C>, Self::Error> {
        let Self {
            data,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            compression_seed,
            ciphertext_modulus,
        } = self;

        Ok(SeededLweKeyswitchKey::from_container_impl(
            data,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            compression_seed,
            ciphertext_modulus,
            true,
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum SeededLweKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(SeededLweKeyswitchKeyV0<C>),
    V1(SeededLweKeyswitchKey<C>),
}
