// Axel '0vercl0k' Souchet - April 22 2024
//! This module contains the implementation of several 'human' types that makes
//! it easy to output a number of bytes, seconds or a quantity into a human
//! form.
use std::fmt::Display;

fn u64_to_f64(x: u64) -> Result<f64, std::fmt::Error> {
    /// This is `2**53` which is the maximum `u64` value that can be represented
    /// as an `f64` (53 bits of mantissa).
    const MAX_U64_REPRESENTABLE_IN_F64: u64 = 9_007_199_254_740_992;

    if x > MAX_U64_REPRESENTABLE_IN_F64 {
        Err(std::fmt::Error)
    } else {
        #[expect(clippy::cast_precision_loss)]
        Ok(x as f64)
    }
}

/// This trait adds convenient functions to display data for Humans. It is the
/// glue between the generic types [`HumanBytes<T>`], [`HumanNumber<T>`] and
/// [`HumanTime<T>`].
pub trait ToHuman: Sized + Copy {
    fn human_bytes(&self) -> HumanBytes<Self> {
        HumanBytes(*self)
    }

    fn human_number(&self) -> HumanNumber<Self> {
        HumanNumber(*self)
    }

    fn human_time(&self) -> HumanTime<Self> {
        HumanTime(*self)
    }
}

/// Blanket implementation for all the `T` that have what we need.
impl<T> ToHuman for T
where
    T: TryInto<u64>,
    T: Copy,
{
}

/// Type that implements [`Display`] to print out a time in human form.
pub struct HumanTime<T>(T);

impl<T> Display for HumanTime<T>
where
    T: TryInto<u64>,
    T: Copy,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut time = u64_to_f64(self.0.try_into().map_err(|_| std::fmt::Error)?)?;
        let mut unit = "s";
        let m = 60f64;
        let h = m * m;
        let d = h * 24.0;
        if time >= m {
            time /= m;
            unit = "min";
        } else if time >= h {
            time /= h;
            unit = "hr";
        } else if time >= d {
            time /= d;
            unit = "day";
        }

        write!(f, "{time:.1}{unit}")
    }
}

/// Type that implements [`Display`] to print out a size in human form.
pub struct HumanBytes<T>(T);

impl<T> Display for HumanBytes<T>
where
    T: Into<u64>,
    T: Copy,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut size = u64_to_f64(self.0.into())?;
        let mut unit = "b";
        let k = 1_024f64;
        let m = k * k;
        let g = m * k;
        if size >= g {
            size /= g;
            unit = "gb";
        } else if size >= m {
            size /= m;
            unit = "mb";
        } else if size >= k {
            size /= k;
            unit = "kb";
        }

        write!(f, "{size:.1}{unit}")
    }
}

/// Type that implements [`Display`] to print out a size in human form.
pub struct HumanNumber<T>(T);

impl<T> Display for HumanNumber<T>
where
    T: TryInto<u64>,
    T: Copy,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut size = u64_to_f64(self.0.try_into().map_err(|_| std::fmt::Error)?)?;
        let mut unit = "";
        let k = 1_000f64;
        let m = k * k;
        let b = m * k;
        if size >= b {
            size /= b;
            unit = "b";
        } else if size >= m {
            size /= m;
            unit = "m";
        } else if size >= k {
            size /= k;
            unit = "k";
        }

        write!(f, "{size:.1}{unit}")
    }
}
