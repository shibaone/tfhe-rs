#![allow(non_snake_case)]

use std::error::Error;
use std::fmt::Display;
use std::marker::PhantomData;

use crate::backward_compatibility::{
    SerializableAffineVersions, SerializableCubicExtFieldVersions, SerializableFpVersions,
    SerializablePublicParamsVersions, SerializableQuadExtFieldVersions,
};
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, Field, Fp, Fp2, Fp6, Fp6Config, FpConfig, QuadExtConfig, QuadExtField};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::curve_api::Curve;
use crate::proofs::pke_v2::PublicParams;
use crate::proofs::GroupElements;

/// Error returned when a conversion from a vec to a fixed size array failed because the vec size is
/// incorrect
#[derive(Debug)]
pub struct InvalidArraySizeError {
    expected_len: usize,
    found_len: usize,
}

impl Display for InvalidArraySizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Invalid serialized array: found array of size {}, expected {}",
            self.found_len, self.expected_len
        )
    }
}

impl Error for InvalidArraySizeError {}

/// Tries to convert a Vec into a constant size array, and returns an [`InvalidArraySizeError`] if
/// the size does not match
fn try_vec_to_array<T, const N: usize>(vec: Vec<T>) -> Result<[T; N], InvalidArraySizeError> {
    let len = vec.len();

    vec.try_into().map_err(|_| InvalidArraySizeError {
        expected_len: len,
        found_len: N,
    })
}

/// Serialization equivalent of the [`Fp`] struct, where the bigint is split into
/// multiple u64.
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(SerializableFpVersions)]
pub struct SerializableFp {
    val: Vec<u64>, // Use a Vec<u64> since serde does not support fixed size arrays with a generic
}

impl<P: FpConfig<N>, const N: usize> From<Fp<P, N>> for SerializableFp {
    fn from(value: Fp<P, N>) -> Self {
        Self {
            val: value.0 .0.to_vec(),
        }
    }
}

impl<P: FpConfig<N>, const N: usize> TryFrom<SerializableFp> for Fp<P, N> {
    type Error = InvalidArraySizeError;

    fn try_from(value: SerializableFp) -> Result<Self, Self::Error> {
        Ok(Fp(BigInt(try_vec_to_array(value.val)?), PhantomData))
    }
}

#[derive(Debug)]
pub struct InvalidSerializedFpError {
    expected_len: usize,
    found_len: usize,
}

impl Display for InvalidSerializedFpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Invalid serialized FP: found array of size {}, expected {}",
            self.found_len, self.expected_len
        )
    }
}

impl Error for InvalidSerializedFpError {}

#[derive(Debug)]
pub enum InvalidSerializedAffineError {
    InvalidFp(InvalidArraySizeError),
    InvalidCompressedXCoordinate,
}

impl Display for InvalidSerializedAffineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidSerializedAffineError::InvalidFp(fp_error) => {
                write!(f, "Invalid fp element in affine: {}", fp_error)
            }
            InvalidSerializedAffineError::InvalidCompressedXCoordinate => {
                write!(
                    f,
                    "Cannot uncompress affine: X coordinate does not belong to the curve"
                )
            }
        }
    }
}

impl Error for InvalidSerializedAffineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            InvalidSerializedAffineError::InvalidFp(fp_error) => Some(fp_error),
            InvalidSerializedAffineError::InvalidCompressedXCoordinate => None,
        }
    }
}

impl From<InvalidArraySizeError> for InvalidSerializedAffineError {
    fn from(value: InvalidArraySizeError) -> Self {
        Self::InvalidFp(value)
    }
}

/// Serialization equivalent to the [`Affine`], which support an optional compression mode
/// where only the `x` coordinate is stored, and the `y` is computed on load.
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(SerializableAffineVersions)]
pub enum SerializableAffine<F> {
    Infinity,
    Compressed { x: F, take_largest_y: bool },
    Uncompressed { x: F, y: F },
}

impl<F> SerializableAffine<F> {
    #[allow(unused)]
    pub fn uncompressed<BaseField: Into<F> + Field, C: SWCurveConfig<BaseField = BaseField>>(
        value: Affine<C>,
    ) -> Self {
        if value.is_zero() {
            Self::Infinity
        } else {
            Self::Uncompressed {
                x: value.x.into(),
                y: value.y.into(),
            }
        }
    }

    pub fn compressed<BaseField: Into<F> + Field, C: SWCurveConfig<BaseField = BaseField>>(
        value: Affine<C>,
    ) -> Self {
        if value.is_zero() {
            Self::Infinity
        } else {
            let take_largest_y = value.y > -value.y;
            Self::Compressed {
                x: value.x.into(),
                take_largest_y,
            }
        }
    }
}

impl<F, C: SWCurveConfig> TryFrom<SerializableAffine<F>> for Affine<C>
where
    F: TryInto<C::BaseField, Error = InvalidArraySizeError>,
{
    type Error = InvalidSerializedAffineError;

    fn try_from(value: SerializableAffine<F>) -> Result<Self, Self::Error> {
        match value {
            SerializableAffine::Infinity => Ok(Self::zero()),
            SerializableAffine::Compressed { x, take_largest_y } => {
                Self::get_point_from_x_unchecked(x.try_into()?, take_largest_y)
                    .ok_or(InvalidSerializedAffineError::InvalidCompressedXCoordinate)
            }
            SerializableAffine::Uncompressed { x, y } => {
                Ok(Self::new_unchecked(x.try_into()?, y.try_into()?))
            }
        }
    }
}

pub(crate) type SerializableG1Affine = SerializableAffine<SerializableFp>;

#[derive(Serialize, Deserialize, Versionize)]
#[versionize(SerializableQuadExtFieldVersions)]
pub struct SerializableQuadExtField<F> {
    c0: F,
    c1: F,
}

pub(crate) type SerializableFp2 = SerializableQuadExtField<SerializableFp>;
pub type SerializableG2Affine = SerializableAffine<SerializableFp2>;

impl<F, P: QuadExtConfig> From<QuadExtField<P>> for SerializableQuadExtField<F>
where
    F: From<P::BaseField>,
{
    fn from(value: QuadExtField<P>) -> Self {
        Self {
            c0: value.c0.into(),
            c1: value.c1.into(),
        }
    }
}

impl<F, P: QuadExtConfig> TryFrom<SerializableQuadExtField<F>> for QuadExtField<P>
where
    F: TryInto<P::BaseField, Error = InvalidArraySizeError>,
{
    type Error = InvalidArraySizeError;

    fn try_from(value: SerializableQuadExtField<F>) -> Result<Self, Self::Error> {
        Ok(QuadExtField {
            c0: value.c0.try_into()?,
            c1: value.c1.try_into()?,
        })
    }
}

#[derive(Serialize, Deserialize, Versionize)]
#[versionize(SerializableCubicExtFieldVersions)]
pub struct SerializableCubicExtField<F> {
    c0: F,
    c1: F,
    c2: F,
}

pub(crate) type SerializableFp6 = SerializableCubicExtField<SerializableFp2>;

impl<F, P6: Fp6Config> From<Fp6<P6>> for SerializableCubicExtField<F>
where
    F: From<Fp2<P6::Fp2Config>>,
{
    fn from(value: Fp6<P6>) -> Self {
        Self {
            c0: value.c0.into(),
            c1: value.c1.into(),
            c2: value.c2.into(),
        }
    }
}

impl<F, P6: Fp6Config> TryFrom<SerializableCubicExtField<F>> for Fp6<P6>
where
    F: TryInto<Fp2<P6::Fp2Config>, Error = InvalidArraySizeError>,
{
    type Error = InvalidArraySizeError;

    fn try_from(value: SerializableCubicExtField<F>) -> Result<Self, Self::Error> {
        Ok(Fp6 {
            c0: value.c0.try_into()?,
            c1: value.c1.try_into()?,
            c2: value.c2.try_into()?,
        })
    }
}

pub(crate) type SerializableFp12 = SerializableQuadExtField<SerializableFp6>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(
    deserialize = "G: Curve, G::G1: serde::Deserialize<'de>, G::G2: serde::Deserialize<'de>",
    serialize = "G: Curve, G::G1: serde::Serialize, G::G2: serde::Serialize"
))]
#[versionize(SerializablePublicParamsVersions)]
pub struct SerializablePublicParams<G: Curve> {
    g_lists: GroupElements<G>,
    D: usize,
    pub n: usize,
    pub d: usize,
    pub k: usize,
    pub B: u64,
    pub B_r: u64,
    pub B_bound: u64,
    pub m_bound: usize,
    pub q: u64,
    pub t: u64,
    // We use Vec<u8> since serde does not support fixed size arrays of 256 elements
    hash: Vec<u8>,
    hash_R: Vec<u8>,
    hash_t: Vec<u8>,
    hash_w: Vec<u8>,
    hash_agg: Vec<u8>,
    hash_lmap: Vec<u8>,
    hash_phi: Vec<u8>,
    hash_xi: Vec<u8>,
    hash_z: Vec<u8>,
    hash_chi: Vec<u8>,
}

impl<G: Curve> From<PublicParams<G>> for SerializablePublicParams<G> {
    fn from(value: PublicParams<G>) -> Self {
        let PublicParams {
            g_lists,
            D,
            n,
            d,
            k,
            B,
            B_r,
            B_bound,
            m_bound,
            q,
            t,
            hash,
            hash_R,
            hash_t,
            hash_w,
            hash_agg,
            hash_lmap,
            hash_phi,
            hash_xi,
            hash_z,
            hash_chi,
        } = value;
        Self {
            g_lists,
            D,
            n,
            d,
            k,
            B,
            B_r,
            B_bound,
            m_bound,
            q,
            t,
            hash: hash.to_vec(),
            hash_R: hash_R.to_vec(),
            hash_t: hash_t.to_vec(),
            hash_w: hash_w.to_vec(),
            hash_agg: hash_agg.to_vec(),
            hash_lmap: hash_lmap.to_vec(),
            hash_phi: hash_phi.to_vec(),
            hash_xi: hash_xi.to_vec(),
            hash_z: hash_z.to_vec(),
            hash_chi: hash_chi.to_vec(),
        }
    }
}

impl<G: Curve> TryFrom<SerializablePublicParams<G>> for PublicParams<G> {
    type Error = InvalidArraySizeError;

    fn try_from(value: SerializablePublicParams<G>) -> Result<Self, Self::Error> {
        let SerializablePublicParams {
            g_lists,
            D,
            n,
            d,
            k,
            B,
            B_r,
            B_bound,
            m_bound,
            q,
            t,
            hash,
            hash_R,
            hash_t,
            hash_w,
            hash_agg,
            hash_lmap,
            hash_phi,
            hash_xi,
            hash_z,
            hash_chi,
        } = value;
        Ok(Self {
            g_lists,
            D,
            n,
            d,
            k,
            B,
            B_r,
            B_bound,
            m_bound,
            q,
            t,
            hash: try_vec_to_array(hash)?,
            hash_R: try_vec_to_array(hash_R)?,
            hash_t: try_vec_to_array(hash_t)?,
            hash_w: try_vec_to_array(hash_w)?,
            hash_agg: try_vec_to_array(hash_agg)?,
            hash_lmap: try_vec_to_array(hash_lmap)?,
            hash_phi: try_vec_to_array(hash_phi)?,
            hash_xi: try_vec_to_array(hash_xi)?,
            hash_z: try_vec_to_array(hash_z)?,
            hash_chi: try_vec_to_array(hash_chi)?,
        })
    }
}
