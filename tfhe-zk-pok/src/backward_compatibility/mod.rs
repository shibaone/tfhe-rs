use tfhe_versionable::VersionsDispatch;

use crate::curve_api::Curve;
use crate::proofs::pke_v2::Proof;
use crate::proofs::GroupElements;
use crate::serialization::{
    SerializableAffine, SerializableCubicExtField, SerializableFp, SerializableFp2,
    SerializableFp6, SerializablePublicParams, SerializableQuadExtField,
};

#[derive(VersionsDispatch)]
pub enum SerializableAffineVersions<F> {
    V0(SerializableAffine<F>),
}

#[derive(VersionsDispatch)]
pub enum SerializableFpVersions {
    V0(SerializableFp),
}

#[derive(VersionsDispatch)]
pub enum SerializableQuadExtFieldVersions<F> {
    V0(SerializableQuadExtField<F>),
}

#[derive(VersionsDispatch)]
pub enum SerializableCubicExtFieldVersions<F> {
    V0(SerializableCubicExtField<F>),
}

pub type SerializableG1AffineVersions = SerializableAffineVersions<SerializableFp>;
pub type SerializableG2AffineVersions = SerializableAffineVersions<SerializableFp2>;
pub type SerializableFp12Versions = SerializableQuadExtFieldVersions<SerializableFp6>;

#[derive(VersionsDispatch)]
pub enum ProofVersions<G: Curve> {
    V0(Proof<G>),
}

#[derive(VersionsDispatch)]
#[allow(dead_code)]
pub(crate) enum GroupElementsVersions<G: Curve> {
    V0(GroupElements<G>),
}

#[derive(VersionsDispatch)]
pub enum SerializablePublicParamsVersions<G: Curve> {
    V0(SerializablePublicParams<G>),
}
