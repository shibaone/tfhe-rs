use std::ops::RangeBounds;

use crate::error::InvalidRangeError;
use crate::high_level_api::ClientKey;
use crate::integer::ciphertext::Expandable;
use crate::{FheBool, Tag};

/// Trait used to have a generic way of creating a value of a FHE type
/// from a native value.
///
/// This trait is for when FHE type the native value is encrypted
/// supports the same numbers of bits of precision.
///
/// The `Key` is required as it contains the key needed to do the
/// actual encryption.
pub trait FheEncrypt<T, Key> {
    fn encrypt(value: T, key: &Key) -> Self;
}

impl<Clear, Key, T> FheEncrypt<Clear, Key> for T
where
    T: FheTryEncrypt<Clear, Key>,
{
    fn encrypt(value: Clear, key: &Key) -> Self {
        T::try_encrypt(value, key).unwrap()
    }
}

// This trait has the same signature than
// `std::convert::From` however we create our own trait
// to be explicit about the `trivial`
pub trait FheTrivialEncrypt<T> {
    fn encrypt_trivial(value: T) -> Self;
}

/// Trait used to have a generic **fallible** way of creating a value of a FHE type.
///
/// For example this trait may be implemented by FHE types which may not be able
/// to represent all the values of even the smallest native type.
///
/// For example, `FheUint2` which has 2 bits of precision may not be constructed from
/// all values that a `u8` can hold.
pub trait FheTryEncrypt<T, Key>
where
    Self: Sized,
{
    type Error: std::error::Error;

    fn try_encrypt(value: T, key: &Key) -> Result<Self, Self::Error>;
}

/// Trait for fallible trivial encryption.
pub trait FheTryTrivialEncrypt<T>
where
    Self: Sized,
{
    type Error: std::error::Error;

    fn try_encrypt_trivial(value: T) -> Result<Self, Self::Error>;
}

/// Decrypt a FHE type to a native type.
pub trait FheDecrypt<T> {
    fn decrypt(&self, key: &ClientKey) -> T;
}

/// Key switch an ciphertext into a new ciphertext of same type but encrypted
/// under a different key.
pub trait FheKeyswitch<T> {
    fn keyswitch(&self, input: &T) -> T;
}

/// Trait for fully homomorphic equality test.
///
/// The standard trait [std::cmp::PartialEq] can not be used
/// has it requires to return a [bool].
///
/// This means that to compare ciphertext to another ciphertext or a scalar,
/// for equality, one cannot use the standard operator `==` but rather, use
/// the function directly.
pub trait FheEq<Rhs = Self> {
    fn eq(&self, other: Rhs) -> FheBool;

    fn ne(&self, other: Rhs) -> FheBool;
}

/// Trait for fully homomorphic comparisons.
///
/// The standard trait [std::cmp::PartialOrd] can not be used
/// has it requires to return a [bool].
///
/// This means that to compare ciphertext to another ciphertext or a scalar,
/// one cannot use the standard operators (`>`, `<`, etc) and must use
/// the functions directly.
pub trait FheOrd<Rhs = Self> {
    fn lt(&self, other: Rhs) -> FheBool;
    fn le(&self, other: Rhs) -> FheBool;
    fn gt(&self, other: Rhs) -> FheBool;
    fn ge(&self, other: Rhs) -> FheBool;
}

pub trait FheMin<Rhs = Self> {
    type Output;

    fn min(&self, other: Rhs) -> Self::Output;
}

pub trait FheMax<Rhs = Self> {
    type Output;

    fn max(&self, other: Rhs) -> Self::Output;
}

/// Trait required to apply univariate function over homomorphic types.
///
/// A `univariate function` is a function with one variable, e.g., of the form f(x).
pub trait FheBootstrap
where
    Self: Sized,
{
    /// Compute a function over an encrypted message, and returns a new encrypted value containing
    /// the result.
    fn map<F: Fn(u64) -> u64>(&self, func: F) -> Self;

    /// Compute a function over the encrypted message.
    fn apply<F: Fn(u64) -> u64>(&mut self, func: F);
}

#[doc(hidden)]
pub trait FheNumberConstant {
    const MIN: u64;
    const MAX: u64;
    const MODULUS: u64;
}

pub trait RotateLeft<Rhs = Self> {
    type Output;

    fn rotate_left(self, amount: Rhs) -> Self::Output;
}

pub trait RotateRight<Rhs = Self> {
    type Output;

    fn rotate_right(self, amount: Rhs) -> Self::Output;
}

pub trait RotateLeftAssign<Rhs = Self> {
    fn rotate_left_assign(&mut self, amount: Rhs);
}

pub trait RotateRightAssign<Rhs = Self> {
    fn rotate_right_assign(&mut self, amount: Rhs);
}

pub trait DivRem<Rhs = Self> {
    type Output;

    fn div_rem(self, amount: Rhs) -> Self::Output;
}

pub trait IfThenElse<Ciphertext> {
    fn if_then_else(&self, ct_then: &Ciphertext, ct_else: &Ciphertext) -> Ciphertext;
    fn select(&self, ct_when_true: &Ciphertext, ct_when_false: &Ciphertext) -> Ciphertext {
        self.if_then_else(ct_when_true, ct_when_false)
    }
    fn cmux(&self, ct_then: &Ciphertext, ct_else: &Ciphertext) -> Ciphertext {
        self.if_then_else(ct_then, ct_else)
    }
}

pub trait OverflowingAdd<Rhs> {
    type Output;

    fn overflowing_add(self, rhs: Rhs) -> (Self::Output, FheBool);
}

pub trait OverflowingSub<Rhs> {
    type Output;

    fn overflowing_sub(self, rhs: Rhs) -> (Self::Output, FheBool);
}

pub trait OverflowingMul<Rhs> {
    type Output;

    fn overflowing_mul(self, rhs: Rhs) -> (Self::Output, FheBool);
}

pub trait BitSlice<Bounds> {
    type Output;

    fn bitslice<R>(self, range: R) -> Result<Self::Output, InvalidRangeError>
    where
        R: RangeBounds<Bounds>;
}

pub trait Tagged {
    fn tag(&self) -> &Tag;

    fn tag_mut(&mut self) -> &mut Tag;
}

pub trait CiphertextList {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes>;
    fn get<T>(&self, index: usize) -> crate::Result<Option<T>>
    where
        T: Expandable + Tagged;
}
