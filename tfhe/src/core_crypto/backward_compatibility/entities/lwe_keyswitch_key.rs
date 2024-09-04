use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::{
    lwe_keyswitch_key_data_compatibility_reverse_levels, CiphertextModulus, Container,
    ContainerMut, DecompositionBaseLog, DecompositionLevelCount, LweKeyswitchKey, LweSize,
    UnsignedInteger,
};

#[derive(Version)]
pub struct LweKeyswitchKeyV0<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_lwe_size: LweSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> Upgrade<LweKeyswitchKey<C>>
    for LweKeyswitchKeyV0<C>
{
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<LweKeyswitchKey<C>, Self::Error> {
        let Self {
            data,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            ciphertext_modulus,
        } = self;
        let mut new_ksk = LweKeyswitchKey::from_container(
            data,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            ciphertext_modulus,
        );

        lwe_keyswitch_key_data_compatibility_reverse_levels(&mut new_ksk);

        Ok(new_ksk)
    }
}

#[derive(VersionsDispatch)]
pub enum LweKeyswitchKeyVersions<C: ContainerMut>
where
    C::Element: UnsignedInteger,
{
    V0(LweKeyswitchKeyV0<C>),
    V1(LweKeyswitchKey<C>),
}
